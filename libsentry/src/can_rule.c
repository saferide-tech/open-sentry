#include <string.h>
#include <stdlib.h>
#include "can_rule.h"
#include "list.h"

static list_t can_rules_list;

typedef struct {
    unsigned short  rulenum;
    unsigned int    tuple_id;
} rule_ids;

/***********************************************************************
 * function:    can_rule_search_cb
 * description: search list display callback. this function will be 
 *              invoked pre node by the list when searching for data 
 * in param:    void *candidate - data contained by node to be examin.
 *              void *data - the data we are searching for.
 * return:      bool (true when found, false otherwise).
 **********************************************************************/
static bool can_rule_search_cb(void *candidate, void *data)
{
    rule_ids *search_id = (rule_ids*)data;
    rule_ids *candidate_id = (rule_ids*)candidate;

    if (search_id->rulenum == candidate_id->rulenum &&
            search_id->tuple_id == candidate_id->tuple_id)
        return true;

    return false;
}

/***********************************************************************
 * function:    can_rule_init
 * description: init the action list
 * return:      int (SENTRY_SUCCESS on complition ok)
 **********************************************************************/
int can_rule_init_list(void)
{
    list_init(&can_rules_list, can_rule_search_cb, NULL, NULL);

    return SENTRY_OK;
}

/***********************************************************************
 * function:    can_rule_clear_list
 * description: delete all elements in the list
 * return:      int (SENTRY_SUCCESS on complition ok)
 **********************************************************************/
void can_rule_clear_list(void)
{
    node_t *ptr = can_rules_list.head;
    rule_ids *can_rule_ids;

    while(ptr) {
        can_rule_ids = list_remove_node(&can_rules_list, ptr);
        if (can_rule_ids)
            free(can_rule_ids);
        ptr = can_rules_list.head;
    }
}

/***********************************************************************
 * function:    can_rule_display
 * description: display the can rule info.
 * in param:    can_rule_t *ptr - can_rule to display.
 * return:      void.
 **********************************************************************/
void can_rule_display(can_rule_t *ptr)
{
    sentry_debug("rule num %d\n", ptr->rulenum);
    sentry_debug("\ttuple %d\n", ptr->tuple.id);
    sentry_debug("\t\taction %s\n", ptr->action_name);
    sentry_debug("\t\tmsg_id 0x%x\n", ptr->tuple.msg_id);
    if (ptr->tuple.direction == SENTRY_DIR_BOTH)
        sentry_debug("\t\tdirection both\n");
    else if (ptr->tuple.direction == SENTRY_DIR_IN)
        sentry_debug("\t\tdirection in\n");
    else if (ptr->tuple.direction == SENTRY_DIR_OUT)
        sentry_debug("\t\tdirection out\n");
    sentry_debug("\t\tinterface %s\n", ptr->tuple.interface);
    sentry_debug("\t\tuser %s\n", ptr->tuple.user);
    sentry_debug("\t\tprogram %s\n", ptr->tuple.program);
    sentry_debug("\t\tmax_rate %d\n", ptr->tuple.max_rate);
}

/***********************************************************************
 * function:    can_rule_get_id
 * description: extract from xpath the rulenum and tuple_id.
 * in param:    char *xpath
 * out param:   can_rule_t *can_rule
 * return:      int (SENTRY_ERR on error, SENTRY_OK on complition ok).
 **********************************************************************/
int can_rule_get_id(can_rule_t *can_rule, char *xpath)
{
    int rulenum, tuple_id, ret;

    /* get the tuple's rulenum and id */
    ret = sscanf(xpath, CAN_TUPLEID_XPATH_FORMAT, &rulenum, &tuple_id);
    if (ret != 2) {
        sentry_error("failed extract rulenum/tuple_id from %s\n", xpath);
        return SENTRY_ERR;
    }

    /* fill new rule info */
    can_rule->rulenum = rulenum;
    can_rule->tuple.id = tuple_id;

    return SENTRY_OK;
}
