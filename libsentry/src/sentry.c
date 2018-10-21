#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <pthread.h>
#include "sysrepo.h"
#include "sysrepo/values.h"
#include "sysrepo/trees.h"
#include "internal_api.h"

sr_conn_ctx_t         *global_connection = NULL;
sr_session_ctx_t      *global_session = NULL;
sr_subscription_ctx_t *global_subscription = NULL;
sentry_callback        sentry_cb = NULL;
bool                   init = false;
static int             current_engine_state = ENGINE_STATE_STOP;
static bool            during_modification = false;

static int  handle_engine_state_change(sr_session_ctx_t *session, int op);

static char *engine_state_str[ENGINE_STATE_TOTAL] = {
    "start",
    "stop",
    "reload",
};

static char *change_xpath_array[SENTRY_ENTRY_TYPE_TOTAL] = {
    STR_ACTION_XPATH,
    STR_CAN_XPATH,
    STR_IP_XPATH,
    STR_FILE_XPATH,
    STR_ENG_XPATH,
};

/***********************************************************************
 * function:    
 * description: 
 * in param:    
 * return:      
 **********************************************************************/
static int sentry_get_entry_type(char *xpath)
{
    int i;

    for (i = 0; i < SENTRY_ENTRY_TYPE_TOTAL; i++) {
        if (strstr(xpath, change_xpath_array[i]))
            return i;
    }

    return SENTRY_ERR;
}

/***********************************************************************
 * function:    sentry_handle_change
 * description: 
 * in param:    
 * return:      
 **********************************************************************/
static void sentry_handle_change(sr_session_ctx_t *session,
                                 int               entry_type,
                                 sr_change_oper_t  op,
                                 sr_val_t         *old_val,
                                 sr_val_t         *new_val)
{
    action_t action;
    ip_rule_t ip_rule;
    can_rule_t can_rule;
    file_rule_t file_rule;
    void *data = NULL;
    int sentry_op = SENTRY_ERR;
    
    switch(op) {
    case SR_OP_CREATED:
        sentry_op = SENTRY_OP_CREATE;
        switch (entry_type) {
        case SENTRY_ENTRY_ACTION:
            /* we are only intrestead with creation of full action */
            if (new_val->type == SR_LIST_T) {
                if (action_create(&action, session, new_val->xpath) != SENTRY_ERR)
                    data = &action;
            }
            break;
        case SENTRY_ENTRY_IP:
            /* we are only intrestead with creation of full tuple */
            if ((new_val->type == SR_LIST_T) && strstr(new_val->xpath, "tuple")) {
                if (ip_rule_create(&ip_rule, session, new_val->xpath) != SENTRY_ERR)
                    data = &ip_rule;
            }
            break;
        case SENTRY_ENTRY_CAN:
            /* we are only intrestead with creation of full tuple */
            if ((new_val->type == SR_LIST_T) && strstr(new_val->xpath, "tuple")) {
                if (can_rule_create(&can_rule, session, new_val->xpath) != SENTRY_ERR)
                    data = &can_rule;
            }
            break;
        case SENTRY_ENTRY_FILE:
            /* we are only intrestead with creation of full tuple */
            if ((new_val->type == SR_LIST_T) && strstr(new_val->xpath, "tuple")) {
                if (file_rule_create(&file_rule, session, new_val->xpath) != SENTRY_ERR)
                    data = &file_rule;
            }
            break;
        case SENTRY_ENTRY_ENG:
            handle_engine_state_change(session, sentry_op);
            break;
        default:
            break;
        }
        break;

    case SR_OP_DELETED:
        /* we dont support deleting of params in action or any other struct */
        sentry_op = SENTRY_OP_DELETE;
        switch (entry_type) {
        case SENTRY_ENTRY_ACTION:
            if ( old_val->type == SR_LIST_T) {
                /* when an action is deleted we can only extract the action name
                 * since its no longer in the database so we will pass the action
                 * struct filled only with the name */
                memset(&action, 0, sizeof(action_t));
                if (action_get_name(&action, old_val->xpath) != SENTRY_ERR)
                    data = &action;
            }
            break;
        case SENTRY_ENTRY_IP:
            /* we are only intrestead with deletion of full tuple */
            if ((old_val->type == SR_LIST_T) && strstr(old_val->xpath, "tuple")) {
                memset(&ip_rule, 0, sizeof(ip_rule_t));
                /* when ip rule is deleted we can only extract the rulenum and
                 * tuple_id since its no longer in the database so we will pass
                 * the ip_rule struct filled only with the those ids */
                if (ip_rule_get_id(&ip_rule, old_val->xpath) != SENTRY_ERR)
                    data = &ip_rule;
            }
            break;
        case SENTRY_ENTRY_CAN:
            /* we are only intrestead with deletion of full tuple */
            if ((old_val->type == SR_LIST_T) && strstr(old_val->xpath, "tuple")) {
                memset(&can_rule, 0, sizeof(can_rule_t));
                /* when can rule is deleted we can only extract the rulenum and
                 * tuple_id since its no longer in the database so we will pass
                 * the can_rule struct filled only with the those ids */
                if (can_rule_get_id(&can_rule, old_val->xpath) != SENTRY_ERR)
                    data = &can_rule;
            }
            break;
        case SENTRY_ENTRY_FILE:
            /* we are only intrestead with deletion of full tuple */
            if ((old_val->type == SR_LIST_T) && strstr(old_val->xpath, "tuple")) {
                memset(&file_rule, 0, sizeof(file_rule_t));
                /* when file rule is deleted we can only extract the rulenum and
                 * tuple_id since its no longer in the database so we will pass
                 * the file_rule struct filled only with the those ids */
                if (file_rule_get_id(&file_rule, old_val->xpath) != SENTRY_ERR)
                    data = &file_rule;
            }
            break;
        case SENTRY_ENTRY_ENG:
            /* engine delete is not supported */
        default:
            break;
        }
        break;

    case SR_OP_MODIFIED:
        sentry_op = SENTRY_OP_MODIFY;
        switch (entry_type) {
        case SENTRY_ENTRY_ACTION:
            if (action_get_modified_action(&action, session, new_val->xpath) != SENTRY_ERR) {
                /* if an action was changed, we need to go over the current existing rules
                 * and check if they need to be updated */
                int ret = SR_ERR_OK, i;
                char rule_xpath[XPATH_MAX_LEN];

                /* first we will update on action chnage */
                sentry_cb(entry_type, sentry_op, &action);

                /* go over the existing rules */
                for (i = SENTRY_ENTRY_CAN; i < SENTRY_ENTRY_ENG; i++) {
                    sr_val_t *values = NULL;
                    size_t count = 0;
                    int j;

                    snprintf(rule_xpath, XPATH_MAX_LEN, "%s/rule", change_xpath_array[i]);
                    ret = sr_get_items(session, rule_xpath, &values, &count);
                    if (ret != SR_ERR_OK)
                        continue;

                    for (j = 0; j < count; j++) {
                        char action_xpath[XPATH_MAX_LEN];
                        sr_val_t *value = NULL;

                        /* found a rule .. lets see if it have the same action */
                        snprintf(action_xpath, XPATH_MAX_LEN, "%s/action", values[j].xpath);

                        ret = sr_get_item(session, action_xpath, &value);
                        if (ret != SR_ERR_OK)
                            continue;

                        if (strncmp(action.action_name, value->data.string_val, strlen(action.action_name)) == 0)
                            /* we need to update the rule's action */
                            sentry_handle_change(session, i, op, NULL, value);

                        sr_free_val(value);
                    }
                    sr_free_values(values, count);
                }
            }
            break;
        case SENTRY_ENTRY_IP:
            ip_rule_get_modified_rule(sentry_cb, session, new_val->xpath);
            break;
        case SENTRY_ENTRY_CAN:
            can_rule_get_modified_rule(sentry_cb, session, new_val->xpath);
            break;
        case SENTRY_ENTRY_FILE:
            file_rule_get_modified_rule(sentry_cb, session, new_val->xpath);
            break;
        case SENTRY_ENTRY_ENG:
            handle_engine_state_change(session, sentry_op);
            break;
        default:
            break;
        }
        break;

    default:
        break;
    }

    if (data && (sentry_op != SENTRY_ERR))
        sentry_cb(entry_type, sentry_op, data);
}

/***********************************************************************
 * function:    saferide_change_cb
 * description: the callback we set into sysrepo to be called upon changes.
 * in param:    
 * return:      SR_ERR_OK
 **********************************************************************/
static int saferide_change_cb(sr_session_ctx_t  *session,
                              const char        *module_name,
                              sr_notif_event_t   event,
                              void              *private_ctx)
{
    sr_change_iter_t *it = NULL;
    int rc = SR_ERR_OK, i;
    sr_change_oper_t oper;
    sr_val_t *old_value = NULL;
    sr_val_t *new_value = NULL;

    /* handle only apply request for now */
    if (event != SR_EV_APPLY)
        return SR_ERR_OK;

    during_modification = true;

    for (i = 0; i < SENTRY_ENTRY_TYPE_TOTAL; i++) {
        /* get the diff changes from last config */
        rc = sr_get_changes_iter(session, change_xpath_array[i], &it);
        if (rc != SR_ERR_OK) {
            sentry_error("sr_get_changes_iter %s failed: (%s)\n",
                change_xpath_array[i], sr_strerror(rc));
            sr_free_change_iter(it);
            continue;
        }

        /* go over the changes and apply them */
        while ((rc = sr_get_change_next(session, it, &oper, &old_value, &new_value)) == SR_ERR_OK) {
            sentry_handle_change(session, i, oper, old_value, new_value);
            sr_free_val(old_value);
            sr_free_val(new_value);
        }

        sr_free_change_iter(it);
    }

    /* aftre each run we need to clear the modified lists */
    action_clear_list();
    ip_rule_clear_list();
    can_rule_clear_list();
    file_rule_clear_list();

    during_modification = false;

    /* notify done */
    sentry_cb(0, 0, NULL);

    return SR_ERR_OK;
}

/***********************************************************************
 * function:    sentry_notify_current_config
 * description: read the current config and notify the user by invoking
 *              the user callback
 * in param:    sr_session_ctx_t *sess
 *              int op - type of change (create/delete)
 *              bool check_engine - update the engine state as well?
 * return:      n/a
 **********************************************************************/
static void sentry_notify_current_config(sr_session_ctx_t *sess, int op)
{
    sr_val_t *values = NULL;
    size_t count = 0;
    int ret = SR_ERR_OK, type, i;
    
    ret = sr_get_items(sess, "/saferide:*//*", &values, &count);
    if (ret != SR_ERR_OK) {
        sentry_error("sr_get_items filed: (%s)\n", sr_strerror(ret));
        return;
    }

    for (i = 0; i < count; i++) {
        if (values[i].type == SR_LIST_T) {
            type = sentry_get_entry_type(values[i].xpath);
            if (type != SENTRY_ERR)
                sentry_handle_change(sess, type, op, &values[i], &values[i]);
        }
    }

    sr_free_values(values, count);
}

/***********************************************************************
 * function:    sentry_init
 * description: init the connection to sysrepo and set the callback
 *              to be called upon relevant db changes
 * in param:    sentry_callback cb - user callback
 * return:      sr_error_t
 **********************************************************************/
int sentry_init(sentry_callback cb)
{
    int rc = SR_ERR_OK;

    sentry_debug("starting sentry\n");

    if (init) {
        sentry_error("already initialized\n");
        return SENTRY_ERR;
    }

    if (!cb) {
        sentry_error("no callback function was provided\n");
        return SENTRY_ERR;
    }

    sentry_cb = cb;
    action_init_list();
    ip_rule_init_list();
    can_rule_init_list();
    file_rule_init_list();

    /* connect to sysrepo */
    rc = sr_connect("sentry", SR_CONN_DEFAULT, &global_connection);
    if (SR_ERR_OK != rc) {
        sentry_error("sr_connect: %s\n", sr_strerror(rc));
        return SENTRY_ERR;
    }

    /* start session */
    rc = sr_session_start(global_connection, SR_DS_STARTUP, SR_SESS_DEFAULT, &global_session);
    if (rc != SR_ERR_OK) {
        sentry_error("sr_session_start: %s\n", sr_strerror(rc));
        sentry_stop();
        return SENTRY_ERR;
    }

    /* subscribe for changes in running config */
    rc = sr_module_change_subscribe(global_session, "saferide",
                                    saferide_change_cb, NULL, 0,
                                    SR_SUBSCR_DEFAULT, &global_subscription);
    if (rc != SR_ERR_OK) {
        sentry_error("sr_module_change_subscribe: %s\n", sr_strerror(rc));
        sentry_stop();
        return SENTRY_ERR;
    }

    handle_engine_state_change(global_session, SR_OP_CREATED);
    sentry_notify_current_config(global_session, SR_OP_CREATED);

    /* mark as initialized */
    init = true;

    sentry_debug("started sentry\n");

    return SENTRY_OK;
}

/***********************************************************************
 * function:    sentry_stop
 * description: close connection to syserpo
 * in param:    n/a
 * return:      SENTRY_OK
 **********************************************************************/
int sentry_stop(void)
{
    int rc = SR_ERR_OK;

    sentry_debug("stoping ...\n");

    if (global_session != NULL) {
        /* copy current running config to startup config */
        rc = sr_copy_config(global_session, "saferide", SR_DS_RUNNING, SR_DS_STARTUP);
        if (rc != SR_ERR_OK)
            sentry_error("sr_copy_config failed: %s\n", sr_strerror(rc));
    }

    /* free various sysrepo stuff */
    if (global_subscription != NULL) {
        rc = sr_unsubscribe(global_session, global_subscription);
        if (rc != SR_ERR_OK)
            sentry_error("sr_unsubscribe failed: %s\n", sr_strerror(rc));
    }

    if (global_session != NULL) {
        rc = sr_session_stop(global_session);
        if (rc != SR_ERR_OK)
            sentry_error("sr_session_stop failed: %s\n", sr_strerror(rc));
    }

    if (global_connection != NULL)
        sr_disconnect(global_connection);

    /* mark as uninitialized */
    init = false;

    action_clear_list();
    ip_rule_clear_list();
    can_rule_clear_list();
    file_rule_clear_list();

    sentry_debug("stopped !!!\n");

    return SENTRY_OK;
}

/***********************************************************************
 * function:    engine_state_str_to_enum
 * description: .
 * in param:    
 * return:      .
 **********************************************************************/
static int engine_state_str_to_enum(char *state)
{
    int i;

    for (i = 0; i < ENGINE_STATE_TOTAL; i++)
        if(strncmp(state, engine_state_str[i], strlen(state)) == 0)
            return i;
    return SENTRY_ERR;
}

/***********************************************************************
 * function:    engine_update_state
 * description: .
 * in param:    
 * return:      .
 **********************************************************************/
void *engine_update_state(void *ptr)
{
    sr_conn_ctx_t *conn = NULL;
    sr_session_ctx_t *session = NULL;
    sr_val_t value = { 0 };
    int ret = SR_ERR_OK;

    while (during_modification)
        usleep(1000);

    sentry_debug("restoring engine state to %s\n", (char*)ptr);

    /* connect to sysrepo */
    ret = sr_connect("os_engine_update_state", SR_CONN_DEFAULT, &conn);
    if (ret != SR_ERR_OK) {
        sentry_error("sr_connect: %s\n", sr_strerror(ret));
        goto cleanup;
    }

    /* start session */
    ret = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
    if (ret != SR_ERR_OK) {
        sentry_error("sr_session_start: %s\n", sr_strerror(ret));
        goto cleanup;
    }

    sentry_debug("prev engine state %s\n", (char*)ptr);
    value.type = SR_STRING_T;
    value.data.string_val = (char *)ptr;
    ret = sr_set_item(session, STR_ENG_XPATH, &value, SR_EDIT_DEFAULT);
    if (ret != SR_ERR_OK) {
        sentry_error("sr_set_item: %s\n", sr_strerror(ret));
        goto cleanup;
    }

    /* commit the changes */
    ret = sr_commit(session);
    if (ret != SR_ERR_OK) {
        sentry_error("sr_commit: %s\n", sr_strerror(ret));
        goto cleanup;
    }

cleanup:
    if (session != NULL) {
        sr_session_stop(session);
    }
    if (conn != NULL) {
        sr_disconnect(conn);
    }
    
    pthread_detach(pthread_self());

    return NULL;
}

/***********************************************************************
 * function:    
 * description: 
 * in param:    
 * return:      
 **********************************************************************/
static int handle_engine_state_change(sr_session_ctx_t *sess, int op)
{
    int engine_state;
    int ret = 0;
    sr_val_t *value = NULL;

    /* get the state */
    ret = sr_get_item(sess, STR_ENG_XPATH, &value);
    if (ret != SR_ERR_OK) {
        sentry_error("sr_get_item (%s)\n", sr_strerror(ret));
        return SENTRY_ERR;
    }

    engine_state = engine_state_str_to_enum(value->data.string_val);

    sr_free_val(value);

    if (engine_state < 0) {
        sentry_error("wrong engine state [%s]\n", value->data.string_val);
        return SENTRY_ERR;
    }

    if (engine_state == current_engine_state) {
        sentry_debug("engine already set to %s\n", value->data.string_val);
        return SENTRY_OK;
    }

    /* notify the user */
    sentry_cb(SENTRY_ENTRY_ENG, op, engine_state_str[engine_state]);

    if (engine_state == ENGINE_STATE_RELOAD) {
        pthread_t thread;

        if (init) {
            /* in reload state we need to delete all current rules and re-apply them */
            sentry_notify_current_config(sess, SR_OP_DELETED);
            sentry_notify_current_config(sess, SR_OP_CREATED);
        }

        /* activate a thread to restore to prev state */
        pthread_create( &thread, NULL, engine_update_state, engine_state_str[current_engine_state]);
    }

    current_engine_state = engine_state;

    sentry_debug("engine state was changed .. \n");

    return SENTRY_OK;
}
