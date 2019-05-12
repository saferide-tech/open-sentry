#include <string.h>
#include <stdlib.h>
#include "file_rule.h"
#include "list.h"

static list_t file_rules_list;

typedef struct {
    unsigned short  rulenum;
    unsigned int    tuple_id;
} rule_ids;

/***********************************************************************
 * function:    file_rule_search_cb
 * description: search list display callback. this function will be 
 *              invoked pre node by the list when searching for data 
 * in param:    void *filedidate - data contained by node to be examin.
 *              void *data - the data we are searching for.
 * return:      bool (true when found, false otherwise).
 **********************************************************************/
static bool file_rule_search_cb(void *filedidate, void *data)
{
    rule_ids *search_id = (rule_ids*)data;
    rule_ids *filedidate_id = (rule_ids*)filedidate;

    if (search_id->rulenum == filedidate_id->rulenum &&
            search_id->tuple_id == filedidate_id->tuple_id)
        return true;

    return false;
}

/***********************************************************************
 * function:    file_rule_init
 * description: init the action list
 * return:      int (SENTRY_SUCCESS on complition ok)
 **********************************************************************/
int file_rule_init_list(void)
{
    list_init(&file_rules_list, file_rule_search_cb, NULL, NULL);

    return SENTRY_OK;
}

/***********************************************************************
 * function:    file_rule_clear_list
 * description: delete all elements in the list
 * return:      int (SENTRY_SUCCESS on complition ok)
 **********************************************************************/
void file_rule_clear_list(void)
{
    node_t *ptr = file_rules_list.head;
    rule_ids *file_rule_ids;

    while(ptr) {
        file_rule_ids = list_remove_node(&file_rules_list, ptr);
        if (file_rule_ids)
            free(file_rule_ids);
        ptr = file_rules_list.head;
    }
}

/***********************************************************************
 * function:    file_rule_display
 * description: display the file rule info.
 * in param:    file_rule_t *ptr - file_rule to display.
 * return:      void.
 **********************************************************************/
void file_rule_display(file_rule_t *ptr)
{
    sentry_debug("rule num %d\n", ptr->rulenum);
    sentry_debug("\ttuple %d\n", ptr->tuple.id);
    sentry_debug("\t\taction %s\n", ptr->action_name);
    sentry_debug("\t\tfilename %s\n", ptr->tuple.filename);
    sentry_debug("\t\tpermission %s\n", ptr->tuple.permission);
    sentry_debug("\t\tuser %s\n", ptr->tuple.user);
    sentry_debug("\t\tprogram %s\n", ptr->tuple.program);
    sentry_debug("\t\tmax_rate %d\n", ptr->tuple.max_rate);
}

/***********************************************************************
 * function:    file_rule_get_id
 * description: extract from xpath the rulenum and tuple_id.
 * in param:    char *xpath
 * out param:   file_rule_t *file_rule
 * return:      int (SENTRY_ERR on error, SENTRY_OK on complition ok).
 **********************************************************************/
int file_rule_get_id(file_rule_t *file_rule, char *xpath)
{
    int rulenum, tuple_id, ret;

    /* get the tuple's rulenum and id */
    ret = sscanf(xpath, FILE_TUPLEID_XPATH_FORMAT, &rulenum, &tuple_id);
    if (ret != 2) {
        sentry_error("failed extract rulenum/tuple_id from %s\n", xpath);
        return SENTRY_ERR;
    }

    /* fill new rule info */
    file_rule->rulenum = rulenum;
    file_rule->tuple.id = tuple_id;

    return SENTRY_OK;
}
