#include <string.h>
#include <stdio.h>
#include <stdlib.h>
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

/***********************************************************************
 * function:    facility_str_to_enum
 * description: convert facility string to enum.
 * in param:    char *facility - facility name.
 * return:      int. SENTRY_ERR on error.
 **********************************************************************/
static char *sentry_log_facility_str[] = {
    "none",
    "syslog",
    "file",
    NULL,
};

/***********************************************************************
 * function:    severity_str_to_enum
 * description: convert severity string to enum.
 * in param:    char* severity - severity name.
 * return:      int. SENTRY_ERR on error.
 **********************************************************************/
char *sentry_log_severity_str[] = {
    "none",
    "critical",
    "error",
    "warning",
    "info",
    "debug",
    NULL,
};

int is_action_value_valid(char *table[], char *value)
{
    int i;

    for (i = 0; table[i]; i++) {
        if (!strcmp(table[i], value))
           return 1;
    }

   return 0;
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

