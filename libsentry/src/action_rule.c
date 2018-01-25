#include <string.h>
#include <stdio.h>
#include "action.h"
#include "list.h"

static list_t actions_list;

/***********************************************************************
 * function:    action_search_cb
 * description: search list display callback. this function will be 
 *              invoked pre node by the list when searching for data 
 * in param:    void *candidate - data contained by node to be examin.
 *              void *data - the data we are searching for.
 * return:      bool (true when found, false otherwise).
 **********************************************************************/
static bool action_search_cb(void *candidate, void *data)
{
    char *search_name = (char*)data;
    char *candidate_name = (char*)candidate;

    if (strncmp(search_name, candidate_name, strlen(search_name)) == 0)
        return true;

    return false;
}

/***********************************************************************
 * function:    action_init_list
 * description: init the action list
 * return:      int (SENTRY_SUCCESS on complition ok)
 **********************************************************************/
int action_init_list(void)
{
    list_init(&actions_list, action_search_cb, NULL, NULL);

    return SENTRY_OK;
}

/***********************************************************************
 * function:    action_clear_list
 * description: delete all elements in the list
 * return:      int (SENTRY_SUCCESS on complition ok)
 **********************************************************************/
void action_clear_list(void)
{
    node_t *ptr = actions_list.head;
    char *action_name;

    while(ptr) {
        action_name = list_remove_node(&actions_list, ptr);
        if (action_name)
            free(action_name);
        ptr = actions_list.head;
    }
}

/***********************************************************************
 * function:    action_str_to_enum
 * description: convert action string to enum.
 * in param:    char *action - action name.
 * return:      int. SENTRY_ERR on error.
 **********************************************************************/
char *sentry_action_str[ACTION_TOTAL] = {
    "none",
    "drop",
    "allow",
};

static int action_str_to_enum(char *action)
{
    int i;

    for (i = 0; i < ACTION_TOTAL; i++)
        if (strncmp(action, sentry_action_str[i], strlen(action)) == 0)
            return i;

    return SENTRY_ERR;
}

/***********************************************************************
 * function:    facility_str_to_enum
 * description: convert facility string to enum.
 * in param:    char *facility - facility name.
 * return:      int. SENTRY_ERR on error.
 **********************************************************************/
static char *sentry_log_facility_str[LOG_TOTAL] = {
    "none",
    "syslog",
    "file",
};

static int facility_str_to_enum(char *facility)
{
    int i;

    for (i = 0; i < LOG_TOTAL; i++)
        if (strncmp(facility, sentry_log_facility_str[i], strlen(facility)) == 0)
            return i;

    return SENTRY_ERR;
}

/***********************************************************************
 * function:    severity_str_to_enum
 * description: convert severity string to enum.
 * in param:    char* severity - severity name.
 * return:      int. SENTRY_ERR on error.
 **********************************************************************/
char *sentry_log_severity_str[LOG_SEVERITY_TOTAL] = {
    "none",
    "critical",
    "error",
    "warning",
    "info",
    "debug",
};

static int severity_str_to_enum(char *severity)
{
    int i;

    for (i = 0; i < LOG_SEVERITY_TOTAL; i++)
        if (strncmp(severity, sentry_log_severity_str[i], strlen(severity)) == 0)
            return i;

    return SENTRY_ERR;
}

/***********************************************************************
 * function:    action_display
 * description: display the action info.
 * in param:    action_t *action - action to display.
 * return:      void.
 **********************************************************************/
void action_display(action_t *action)
{
    if (action && (strlen(action->action_name) > 0 )) {
        sentry_debug("action:\n");
        sentry_debug("\taction name %s\n", action->action_name);
        sentry_debug("\taction %s\n", sentry_action_str[action->action]);
        sentry_debug("\tlog_facility %s\n", sentry_log_facility_str[action->log_facility]);
        sentry_debug("\tlog_severity %s\n", sentry_log_severity_str[action->log_severity]);
        sentry_debug("\tblack_list %s\n", action->black_list?"true":"false");
        sentry_debug("\tterminate %s\n", action->terminate?"true":"false");
    }
}

/***********************************************************************
 * function:    action_extract_log
 * description: extract the logging info.
 * in param:    sr_session_ctx_t *session.
 *              char* xpath - the xpath of the logging info.
 * out param:   action_t *action - the action we should update.
 * return:      int (SENTRY_ERR on error, SENTRY_OK on complition ok).
 **********************************************************************/
static int action_extract_log(sr_session_ctx_t *session,
                              char             *xpath,
                              action_t         *action)
{
    sr_val_t *values = NULL;
    size_t count = 0;
    int i, len;
    int rc = SR_ERR_OK;
    char log_xpath[XPATH_MAX_LEN] = {0};
    char *value_name;

    /* get the number of params in log container */
    strncat(log_xpath, xpath, XPATH_MAX_LEN-3);
    strcat(log_xpath, "//*");
    rc = sr_get_items(session, log_xpath, &values, &count);
    if (rc != SR_ERR_OK) {
        sentry_error("sr_get_items (%s)\n", sr_strerror(rc));
        return rc;
    }

    /* go over the params in log container and fill the action with the info */
    for (i = 0; i < count; i++) {
        value_name = strrchr(values[i].xpath, '/');
        if (value_name) {
            value_name++;

            len = strlen(value_name);

            if (strncmp(value_name, "log_facility", len) == 0)
                action->log_facility = 
                    facility_str_to_enum(values[i].data.string_val);

            if (strncmp(value_name, "log_severity", len) == 0)
                action->log_severity = 
                    severity_str_to_enum(values[i].data.string_val);
        }
    }

    sr_free_values(values, count);

    return SENTRY_OK;
}

/***********************************************************************
 * function:    action_create
 * description: extract all relevant info and set it in ation.
 * in param:    sr_session_ctx_t *sess
                char *xpath
 * out params:  action_t *action
 * return:      int (SENTRY_ERR on error, SENTRY_OK on complition ok).
 **********************************************************************/
int action_create(action_t         *action,
                  sr_session_ctx_t *sess,
                  char             *xpath)
{
    sr_val_t *values = NULL;
    size_t count = 0;
    int i, len;
    int rc = SR_ERR_OK;
    char action_xpath[XPATH_MAX_LEN];
    char *value_name;

    memset(action, 0, sizeof(action_t));

    /* get all params in this action */
    snprintf(action_xpath, XPATH_MAX_LEN, "%s//*", xpath);
    rc = sr_get_items(sess, action_xpath, &values, &count);
    if (rc != SR_ERR_OK) {
        sentry_error("sr_get_items %s failed: %s\n", action_xpath, sr_strerror(rc));
        return SENTRY_ERR;
    }

    /* go over the items and fill the action with the info */
    for (i = 0; i < count; i++) {
        value_name = strrchr(values[i].xpath, '/');
        if (value_name) {
            value_name++;
            len = strlen(value_name);

            /* get the action's name */
            if (strncmp(value_name, "name", len) == 0)
                strncpy(action->action_name, values[i].data.string_val,
                    ACTION_STR_SIZE);

            /* get the action's action */
            else if (strncmp(value_name, "action", len) == 0)
                action->action = action_str_to_enum(values[i].data.string_val);

            /* get the action's black_list */
            else if (strncmp(value_name, "black-list", len) == 0)
                action->black_list = values[i].data.bool_val;

            /* get the action's terminate */
            else if (strncmp(value_name, "terminate", len) == 0)
                action->terminate = values[i].data.bool_val;

            /* get the action's log */
            else if (strncmp(value_name, "log", len) == 0)
                action_extract_log(sess, values[i].xpath, action);
        }
    }

    sr_free_values(values, count);

    return SENTRY_OK;
}

/***********************************************************************
 * function:    action_get_modified_action
 * description: return action_t* based on xpath of modified value
 * in param:    sr_session_ctx_t *sess
                char *xpath
 * out param:   action_t *action
 * return:      SENTRY_ERR or SENTRY_OK.
 **********************************************************************/
int action_get_modified_action(action_t         *action,
                               sr_session_ctx_t *sess,
                               char             *xpath)
{
    char action_xpath[XPATH_MAX_LEN];
    char *tmp = NULL;

    /* we need to extract  /saferide:config/sr_actions/list_actions[name='???'] */
    tmp = strrchr(xpath, ']');
    if (!tmp) {
        sentry_error("action name [%s] syntax is wrong\n", xpath);
        return SENTRY_ERR;
    }
    tmp += 1;
    memset(action_xpath, 0, XPATH_MAX_LEN);
    memcpy(action_xpath, xpath, (tmp-xpath));

    if (action_create(action, sess, action_xpath) != SENTRY_OK)
        return SENTRY_ERR;

    if (list_search_node(&actions_list, action->action_name)) {
        sentry_debug("action %s was already handled\n", action->action_name);
        return SENTRY_ERR;
    } else {
        char *action_name = malloc(ACTION_STR_SIZE);
        snprintf(action_name, ACTION_STR_SIZE, "%s", action->action_name);
        list_append(&actions_list, action_name);
    }

    return SENTRY_OK;
}

/***********************************************************************
 * function:    action_get_name
 * description: extract the action name and set in action->action_name
 * in param:    char *xpath
 * out param:   action_t *action
 * return:      SENTRY_ERR or SENTRY_OK.
 **********************************************************************/
int action_get_name(action_t *action, char *xpath)
{
    char action_name[XPATH_MAX_LEN]={0};
    char *tmp = NULL;
    int ret;

    /* get the action name */
    ret = sscanf(xpath, ACTION_NAME_XPATH_PREFIX, action_name);
    if (ret != 1) {
        sentry_error("couldn't extract action name\n");
        return SENTRY_ERR;
    }

    tmp = strrchr(action_name, '\'');
    if (!tmp) {
        sentry_error("action name [%s] syntax is wrong\n", action_name);
        return SENTRY_ERR;
    }
    *tmp = 0;

    snprintf(action->action_name, ACTION_STR_SIZE, "%s", action_name);

    return SENTRY_OK;
}
