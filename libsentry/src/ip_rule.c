#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "ip_rule.h"
#include "list.h"

static list_t ip_rules_list;

typedef struct {
    unsigned short  rulenum;
    unsigned int    tuple_id;
} rule_ids;

/***********************************************************************
 * function:    ip_rule_search_cb
 * description: search list display callback. this function will be 
 *              invoked pre node by the list when searching for data 
 * in param:    void *candidate - data contained by node to be examin.
 *              void *data - the data we are searching for.
 * return:      bool (true when found, false otherwise).
 **********************************************************************/
static bool ip_rule_search_cb(void *candidate, void *data)
{
    rule_ids *search_id = (rule_ids*)data;
    rule_ids *candidate_id = (rule_ids*)candidate;

    if (search_id->rulenum == candidate_id->rulenum &&
            search_id->tuple_id == candidate_id->tuple_id)
        return true;

    return false;
}

/***********************************************************************
 * function:    ip_rule_init
 * description: init the action list
 * return:      int (SENTRY_SUCCESS on complition ok)
 **********************************************************************/
int ip_rule_init_list(void)
{
    list_init(&ip_rules_list, ip_rule_search_cb, NULL, NULL);

    return SENTRY_OK;
}

/***********************************************************************
 * function:    ip_rule_clear_list
 * description: delete all elements in the list
 * return:      int (SENTRY_SUCCESS on complition ok)
 **********************************************************************/
void ip_rule_clear_list(void)
{
    node_t *ptr = ip_rules_list.head;
    rule_ids *ip_rule_ids;

    while(ptr) {
        ip_rule_ids = list_remove_node(&ip_rules_list, ptr);
        if (ip_rule_ids)
            free(ip_rule_ids);
        ptr = ip_rules_list.head;
    }
}

/***********************************************************************
 * function:    ip_rule_display
 * description: display the ip_rule info.
 * in param:    ip_rules_t *ptr - ip_rule to display.
 * return:      void.
 **********************************************************************/
void ip_rule_display(ip_rule_t *ptr)
{
    sentry_debug("rule num %d\n", ptr->rulenum);
    sentry_debug("\ttuple %d\n", ptr->tuple.id);
    sentry_debug("\t\taction %s\n", ptr->action_name);
    sentry_debug("\t\tsrcaddr %s\n", inet_ntoa(ptr->tuple.srcaddr));
    sentry_debug("\t\tsrcnetmask %s\n", inet_ntoa(ptr->tuple.srcnetmask));
    sentry_debug("\t\tdstaddr %s\n", inet_ntoa(ptr->tuple.dstaddr));
    sentry_debug("\t\tdstnetmask %s\n", inet_ntoa(ptr->tuple.dstnetmask));
    sentry_debug("\t\tsrcport %u\n", ptr->tuple.srcport);
    sentry_debug("\t\tdstport %u\n", ptr->tuple.dstport);
    sentry_debug("\t\tproto %u\n", ptr->tuple.proto);
    sentry_debug("\t\tuser %s\n", ptr->tuple.user);
    sentry_debug("\t\tprogram %s\n", ptr->tuple.program);
    sentry_debug("\t\tmax_rate %d\n", ptr->tuple.max_rate);
}

/***********************************************************************
 * function:    ip_rule_get_id
 * description: extract from xpath the rulenum and tuple_id.
 * in param:    char *xpath
 * out param:   ip_rule_t *ip_rule
 * return:      int (SENTRY_ERR on error, SENTRY_OK on complition ok).
 **********************************************************************/
int ip_rule_get_id(ip_rule_t *ip_rule, char *xpath)
{
    int rulenum, tuple_id, ret;

    /* get the tuple's rulenum and id */
    ret = sscanf(xpath, IP_TUPLEID_XPATH_FORMAT, &rulenum, &tuple_id);
    if (ret != 2) {
        sentry_error("failed extract rulenum/tuple_id from %s\n", xpath);
        return SENTRY_ERR;
    }

    /* fill new rule info */
    ip_rule->rulenum = rulenum;
    ip_rule->tuple.id = tuple_id;

    return SENTRY_OK;
}
