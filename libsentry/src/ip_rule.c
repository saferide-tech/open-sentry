#include <string.h>
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
 * function:    ip_rule_get_action
 * description: get the action related to ip rule if exists.
 * in param:    sr_session_ctx_t *session.
 *              int rulenum.
 * out param:   ip_rule_t *ip_rule
 * return:      int (SENTRY_ERR on error, SENTRY_OK on complition ok).
 **********************************************************************/
int ip_rule_get_action(ip_rule_t        *ip_rule,
                       sr_session_ctx_t *session,
                       int               rulenum)
{
    char action_xpath[XPATH_MAX_LEN];
    sr_val_t *value = NULL;
    int ret;

    /* constract the action's xpath*/
    snprintf(action_xpath, XPATH_MAX_LEN, IP_RULE_ACT_XPATH_FORMAT, rulenum);

    /* get the action related to this ip rule */
    ret = sr_get_item(session, action_xpath, &value);
    if (ret != SR_ERR_OK) {
        sentry_error("sr_get_item filed: (%s)\n", sr_strerror(ret));
        ret = SENTRY_ERR;
    } else {
        snprintf(ip_rule->action_name, ACTION_STR_SIZE, "%s", value->data.string_val);
        ret = SENTRY_OK;
    }

    sr_free_val(value);

    return ret;
}

/***********************************************************************
 * function:    ip_rule_extract_tuple
 * description: extract all relevant ip tuple info and set it in tuple.
 * in param:    sr_session_ctx_t *session
 *              char *xpath,
 * out param:   ip_tuple_t *tuple
 * return:      int (SENTRY_ERR on error, SENTRY_OK on complition ok).
 **********************************************************************/
static int ip_rule_extract_tuple(sr_session_ctx_t *session,
                                 char             *xpath,
                                 ip_tuple_t       *tuple)
{
    sr_val_t *values = NULL;
    size_t count = 0;
    int rc = SENTRY_OK, i, len;
    char tuple_xpath[XPATH_MAX_LEN] = {0};
    char *value_name;

    /* get the tuple info */
    snprintf(tuple_xpath, XPATH_MAX_LEN, "%s/*", xpath);
    rc = sr_get_items(session, tuple_xpath, &values, &count);
    if (rc != SR_ERR_OK) {
        sentry_error("sr_get_items (%s)\n", sr_strerror(rc));
        return SENTRY_ERR;
    }

    memset(tuple, 0, sizeof(ip_tuple_t));

    for (i = 0; i < count; i++) {
        value_name = strrchr(values[i].xpath, '/');
        if (value_name) {
            value_name++;
            len = strlen(value_name);

            /* get the tuple's id */
            if (strncmp(value_name, "id", len) == 0)
                tuple->id = values[i].data.uint32_val;

            else if (strncmp(value_name, "srcaddr", len) == 0)
                inet_pton(AF_INET, values[i].data.string_val, &tuple->srcaddr);

            else if (strncmp(value_name, "srcnetmask", len) == 0)
                inet_pton(AF_INET, values[i].data.string_val,
                    &tuple->srcnetmask);

            else if (strncmp(value_name, "dstaddr", len) == 0)
                inet_pton(AF_INET, values[i].data.string_val, &tuple->dstaddr);

            else if (strncmp(value_name, "dstnetmask", len) == 0)
                inet_pton(AF_INET, values[i].data.string_val,
                    &tuple->dstnetmask);

            else if (strncmp(value_name, "srcport", len) == 0)
                tuple->srcport = values[i].data.uint16_val;

            else if (strncmp(value_name, "dstport", len) == 0)
                tuple->dstport = values[i].data.uint16_val;

            else if (strncmp(value_name, "proto", len) == 0)
                tuple->proto = values[i].data.uint8_val;

            else if (strncmp(value_name, "user", len) == 0)
                strncpy(tuple->user, values[i].data.string_val,
                    USER_NAME_SIZE);

            else if (strncmp(value_name, "program", len) == 0)
                strncpy(tuple->program, values[i].data.string_val,
                    PROG_NAME_SIZE);

            else if (strncmp(value_name, "max_rate", len) == 0)
                tuple->max_rate = values[i].data.uint32_val;
        }
    }

    sr_free_values(values, count);

    return SENTRY_OK;
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

/***********************************************************************
 * function:    ip_rules_create
 * description: extract all relevant ip rule info and set it in ip_rule.
 * in param:    sr_session_ctx_t *sess
 *              char *xpath
 * out param:   ip_rule_t *ip_rule
 * return:      int (SENTRY_ERR on error, SENTRY_OK on complition ok).
 **********************************************************************/
int ip_rule_create(ip_rule_t        *ip_rule,
                   sr_session_ctx_t *sess,
                   char             *xpath)
{
    int ret = SENTRY_OK;

    if (ip_rule_get_id(ip_rule, xpath) != SENTRY_OK) {
        sentry_error("failed extract rulenum/tuple_id from %s\n", xpath);
        return SENTRY_ERR;
    }

    /* get the rule's action */
    if (ip_rule_get_action(ip_rule, sess, ip_rule->rulenum) != SENTRY_OK)
        sentry_warn("ip rule %d have no action\n", ip_rule->rulenum);

    ret = ip_rule_extract_tuple(sess, xpath, &ip_rule->tuple);
    if (ret != SENTRY_OK) {
        sentry_error("failed to extract ip tuple from %s\n", xpath);
        return SENTRY_ERR;
    }

    return SENTRY_OK;
}

/***********************************************************************
 * function:    ip_rule_get_modified_rule
 * description: for ip rule, the modification can be on 2 different levels:
 *              1. one of the tuple's params was modified, i.e. single
 *                 tuple modification.
 *              2. the rule's action was changed and we need to update all
 *                 related tuples, i.e. multiple tuples modifications.
 * in param:    sr_session_ctx_t *sess
 *              char *xpath
 * out param:   ip_rule_t *ip_rule
 * return:      int (SENTRY_ERR on error, SENTRY_OK on complition ok).
 **********************************************************************/
int ip_rule_get_modified_rule(sentry_callback   cb,
                              sr_session_ctx_t *sess,
                              char             *xpath)
{
    int rulenum, tuple_id, ret;
    char rule_xpath[XPATH_MAX_LEN];
    char param[XPATH_MAX_LEN];
    char *ptr;
    ip_rule_t ip_rule;
    rule_ids ids;

    /* go to the last '/' */
    ptr = strrchr(xpath, '/');
    if (!ptr) {
        sentry_error("%s syntax is wrong\n", xpath);
        return SENTRY_ERR;
    }
    ptr++;

    /* search for /saferide:config/net/ip/rule[num='1']/action */
    if (strncmp(ptr, "action", strlen(ptr)) == 0) {
        /* the rule action was modified .. multiple tuples modifications */
        sr_val_t *values = NULL;
        size_t count = 0, i;

        /* get the rulenum */
        ret = sscanf(xpath, IP_RULE_ACT_XPATH_FORMAT, &rulenum);
        if (ret != 1) {
            sentry_error("failed to extract rulenum\n");
            return SENTRY_ERR;
        }

        /* get the rule tuples */
        snprintf(rule_xpath, XPATH_MAX_LEN, IP_TUPLES_XPATH_FORMAT, rulenum);
        ret = sr_get_items(sess, rule_xpath, &values, &count);
        if (ret != SR_ERR_OK) {
            sentry_error("sr_get_items (%s)\n", sr_strerror(ret));
            return SENTRY_ERR;
        }

        for (i = 0; i < count; i++) {
            if (ip_rule_create(&ip_rule,  sess, values[i].xpath) != SENTRY_OK) {
                sentry_error("failed to create ip rule from %s\n", values[i].xpath);
                continue;
            }

            /* check if we need to notify the user about this modification */
            ids.rulenum = ip_rule.rulenum;
            ids.tuple_id = ip_rule.tuple.id;
            if (list_search_node(&ip_rules_list, &ids)) {
                sentry_debug("ip rulenum %d tuple_id %d was already handled\n", ids.rulenum, ids.tuple_id);
                continue;
            } else {
                rule_ids *new_ids = malloc(sizeof(rule_ids));
                new_ids->rulenum = ip_rule.rulenum;
                new_ids->tuple_id = ip_rule.tuple.id;
                list_append(&ip_rules_list, new_ids);
                cb(SENTRY_ENTRY_IP, SENTRY_OP_MODIFY, &ip_rule);
            }
        }
        sr_free_values(values, count);
    } else {
        /* need to update only single tuple */
        ret = sscanf(xpath, IP_TUPLEID_XPATH_FORMAT"/%s", &rulenum, &tuple_id, param);
        if (ret != 3) {
            sentry_error("failed to get updated param info\n");
            return SENTRY_ERR;
        }

        snprintf(rule_xpath, XPATH_MAX_LEN, IP_TUPLEID_XPATH_FORMAT, rulenum, tuple_id);
        if (ip_rule_create(&ip_rule,  sess, rule_xpath) != SENTRY_OK) {
            sentry_error("failed to create ip rule from %s\n", rule_xpath);
            return SENTRY_ERR;
        }

        /* check if we need to notify the user about this modification */
        ids.rulenum = ip_rule.rulenum;
        ids.tuple_id = ip_rule.tuple.id;
        if (list_search_node(&ip_rules_list, &ids)) {
            sentry_debug("ip rulenum %d tuple_id %d was already handled\n", ids.rulenum, ids.tuple_id);
            return SENTRY_ERR;
        } else {
            rule_ids *new_ids = malloc(sizeof(rule_ids));
            new_ids->rulenum = ip_rule.rulenum;
            new_ids->tuple_id = ip_rule.tuple.id;
            list_append(&ip_rules_list, new_ids);
            cb(SENTRY_ENTRY_IP, SENTRY_OP_MODIFY, &ip_rule);
        }
    }

    return SENTRY_OK;
}
