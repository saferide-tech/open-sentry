#include <string.h>
#include <stdbool.h>
#include "list.h"
#include "action_module.h"

/* global actions list */
static list_t actions_list;

/***********************************************************************
 * function:    action_search_cb
 * description: search list display callback. this function will be 
 *              invoked pre node by the list when searching for data 
 * in param:    void* candidate - data contained by node to be examin.
 *              void* data - the data we are searching for.
 * return:      bool (true when found, false otherwise).
 **********************************************************************/
static bool action_search_cb(void* candidate, void* data)
{
    char *action_name = (char*)data;
    action_t* action = (action_t*)candidate;

    if (strncmp(action_name, action->action_name, strlen(action_name)) == 0)
        return true;

    return false;
}

/***********************************************************************
 * function:    action_init
 * description: init the action list
 * return:      n/a
 **********************************************************************/
void action_init(void)
{
    list_init(&actions_list, action_search_cb, NULL, NULL);
}

/***********************************************************************
 * function:    action_deinit
 * description: free all elements in action list
 * return:      n/a
 **********************************************************************/
void action_deinit(void)
{
    node_t *ptr = actions_list.head;
    action_t *action;

    while(ptr) {
        action = list_remove_node(&actions_list, ptr);
        if (action)
            free(action);
        ptr = actions_list.head;
    }
}

/***********************************************************************
 * function:    action_search_by_name
 * description: search for an action in the list by name.
 * in param:    char *name - the action name.
 * return:      action_t*
 **********************************************************************/
action_t* action_search_by_name(char *name)
{
    node_t* candidate = NULL;

    candidate = list_search_node(&actions_list, name);
    if (!candidate)
        return NULL;

    return (action_t*)candidate->data;
}

/***********************************************************************
 * function:    action_create
 * description: add new action to actios_list
 * in param:    action_t *new_action
 * return:      SENTRY_OK/SENTRY_ERR
 **********************************************************************/
static int action_create(action_t *action)
{
    action_t *new_action = NULL;

    if (!action)
        return SENTRY_ERR;

    new_action = action_search_by_name(action->action_name);
    if (new_action) {
        sentry_error("action %s already exist\n", action->action_name);
        return SENTRY_ERR;
    }

    /* alocate new action_t struct */
    new_action = malloc(sizeof(action_t));
    if (!new_action) {
        sentry_error("cant allocate memory for new action\n");
        return SENTRY_ERR;
    }

    memcpy(new_action, action, sizeof(action_t));

    /* add the new action to list */
    if (list_append(&actions_list, new_action) == NULL) {
        sentry_error("failed to add the new action to list\n");
        free(new_action);
        return SENTRY_ERR;
    }

    sentry_debug("created action %s\n", action->action_name);

    return SENTRY_OK;
}

/***********************************************************************
 * function:    action_delete
 * description: delete an action from the list. search by ref action
 * in param:    action_t *
 * return:      SENTRY_OK/SENTRY_ERR
 **********************************************************************/
static int action_delete(action_t *action)
{
    node_t* candidate = NULL;
    action_t* del_action = NULL;

    if (!action)
        return SENTRY_ERR;

    candidate = list_search_node(&actions_list, action->action_name);
    if (!candidate) {
        sentry_error("couldn't find action name %s\n", action->action_name);
        return SENTRY_ERR;
    }

    if ((del_action = list_remove_node(&actions_list, candidate)) == NULL) {
        sentry_error("failed to remove node\n");
        return SENTRY_ERR;
    }

    free(del_action);

    sentry_debug("deleted action %s\n", action->action_name);

    return SENTRY_OK;
}

/***********************************************************************
 * function:    action_modify
 * description: modify an action on the list. search by ref action
 * in param:    action_t *
 * return:      SENTRY_OK/SENTRY_ERR
 **********************************************************************/
static int action_modify(action_t *action)
{
    action_t *mod_action = NULL;

    sentry_debug("\n");

    if (!action)
        return SENTRY_ERR;

    mod_action = action_search_by_name(action->action_name);
    if (!mod_action) {
        sentry_error("couldn't find action name %s\n", action->action_name);
        return SENTRY_ERR;
    }

    /* copy data */
    memcpy(mod_action, action, sizeof(action_t));

    sentry_debug("modified action %s\n", action->action_name);

    return SENTRY_OK;
}

/***********************************************************************
 * function:    action_handle_event
 * description: handle action event
 * in param:    action_t *
 * return:      SENTRY_OK/SENTRY_ERR
 **********************************************************************/
int action_handle_event(int op, action_t *action)
{
    switch (op) {
    case SENTRY_OP_CREATE:
        return action_create(action);
    case SENTRY_OP_DELETE:
        return action_delete(action);
    case SENTRY_OP_MODIFY:
        return action_modify(action);
    default:
        return SENTRY_ERR;
    }
}
