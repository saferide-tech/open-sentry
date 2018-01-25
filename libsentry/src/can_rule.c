#include <string.h>
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
    sentry_debug("\t\tuser %s\n", ptr->tuple.user);
    sentry_debug("\t\tprogram %s\n", ptr->tuple.program);
    sentry_debug("\t\tmax_rate %d\n", ptr->tuple.max_rate);
}

/***********************************************************************
 * function:    can_rule_get_action
 * description: get the action related to can rule if exists.
 * in param:    sr_session_ctx_t *session.
 *              int rulenum.
 * out param:   can_rule_t *can_rule
 * return:      int (SENTRY_ERR on error, SENTRY_OK on complition ok).
 **********************************************************************/
int can_rule_get_action(can_rule_t      *can_rule,
                       sr_session_ctx_t *session,
                       int               rulenum)
{
    char action_xpath[XPATH_MAX_LEN];
    sr_val_t *value = NULL;
    int ret;

    /* constract the action's xpath*/
    snprintf(action_xpath, XPATH_MAX_LEN, CAN_RULE_ACT_XPATH_FORMAT, rulenum);

    /* get the action related to this ip rule */
    ret = sr_get_item(session, action_xpath, &value);
    if (ret != SR_ERR_OK) {
        sentry_error("sr_get_item filed: (%s)\n", sr_strerror(ret));
        ret = SENTRY_ERR;
    } else {
        snprintf(can_rule->action_name, ACTION_STR_SIZE, "%s", value->data.string_val);
        ret = SENTRY_OK;
    }

    sr_free_val(value);

    return ret;
}

/***********************************************************************
 * function:    can_rule_extract_tuple
 * description: extract all relevant can tuple info and set it in tuple.
 * in param:    sr_session_ctx_t *session
 *              char *xpath,
 * out param:   can_tuple_t *tuple
 * return:      int (SENTRY_ERR on error, SENTRY_OK on complition ok).
 **********************************************************************/
static int can_rule_extract_tuple(sr_session_ctx_t *session,
                                  char             *xpath,
                                  can_tuple_t      *tuple)
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

    memset(tuple, 0, sizeof(can_tuple_t));

    for (i = 0; i < count; i++) {
        value_name = strrchr(values[i].xpath, '/');
        if (value_name) {
            value_name++;
            len = strlen(value_name);

            /* get the tuple's id */
            if (strncmp(value_name, "id", len) == 0)
                tuple->id = values[i].data.uint32_val;

            else if (strncmp(value_name, "msg_id", len) == 0) {
                /* check if this is a default filter */
                if (strncmp(values[i].data.string_val, "any", 3) == 0)
                    tuple->msg_id = (unsigned int)(-1);
                else
                    sscanf(values[i].data.string_val, "%x", &tuple->msg_id);
            }

            else if (strncmp(value_name, "direction", len) == 0) {
                if (strncmp(values[i].data.string_val, "both",
                        strlen(values[i].data.string_val)) == 0)
                    tuple->direction = SENTRY_DIR_BOTH;
                else if (strncmp(values[i].data.string_val, "in",
                        strlen(values[i].data.string_val)) == 0)
                    tuple->direction = SENTRY_DIR_IN;
                else if (strncmp(values[i].data.string_val, "out",
                        strlen(values[i].data.string_val)) == 0)
                    tuple->direction = SENTRY_DIR_OUT;
            }

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

/***********************************************************************
 * function:    can_rule_create
 * description: extract all relevant can rule info and set it in can_rule.
 * in param:    sr_session_ctx_t *sess
 *              char *xpath
 * out param:   can_rule_t *can_rule
 * return:      int (SENTRY_ERR on error, SENTRY_OK on complition ok).
 **********************************************************************/
int can_rule_create(can_rule_t       *can_rule,
                    sr_session_ctx_t *sess,
                    char             *xpath)
{
    int ret = SENTRY_OK;

    if (can_rule_get_id(can_rule, xpath) != SENTRY_OK) {
        sentry_error("failed extract rulenum/tuple_id from %s\n", xpath);
        return SENTRY_ERR;
    }

    /* get the rule's action */
    if (can_rule_get_action(can_rule, sess, can_rule->rulenum) != SENTRY_OK)
        sentry_warn("can rule %d have no action\n", can_rule->rulenum);

    ret = can_rule_extract_tuple(sess, xpath, &can_rule->tuple);
    if (ret != SENTRY_OK) {
        sentry_error("failed to extract ip tuple from %s\n", xpath);
        return SENTRY_ERR;
    }

    return SENTRY_OK;
}

/***********************************************************************
 * function:    can_rule_get_modified_rule
 * description: for can rule, the modification can be on 2 different levels:
 *              1. one of the tuple's params was modified, i.e. single
 *                 tuple modification.
 *              2. the rule's action was changed and we need to update all
 *                 related tuples, i.e. multiple tuples modifications.
 * in param:    sr_session_ctx_t *sess
 *              char *xpath
 * out param:   can_rule_t *can_rule
 * return:      int (SENTRY_ERR on error, SENTRY_OK on complition ok).
 **********************************************************************/
int can_rule_get_modified_rule(sentry_callback   cb,
                               sr_session_ctx_t *sess,
                               char             *xpath)
{
    int rulenum, tuple_id, ret;
    char rule_xpath[XPATH_MAX_LEN];
    char param[XPATH_MAX_LEN];
    char *ptr;
    can_rule_t can_rule;
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
        ret = sscanf(xpath, CAN_RULE_ACT_XPATH_FORMAT, &rulenum);
        if (ret != 1) {
            sentry_error("failed to extract rulenum\n");
            return SENTRY_ERR;
        }

        /* get the rule tuples */
        snprintf(rule_xpath, XPATH_MAX_LEN, CAN_TUPLES_XPATH_FORMAT, rulenum);
        ret = sr_get_items(sess, rule_xpath, &values, &count);
        if (ret != SR_ERR_OK) {
            sentry_error("sr_get_items (%s)\n", sr_strerror(ret));
            return SENTRY_ERR;
        }

        for (i = 0; i < count; i++) {
            if (can_rule_create(&can_rule,  sess, values[i].xpath) != SENTRY_OK) {
                sentry_error("failed to create ip rule from %s\n", values[i].xpath);
                continue;
            }

            /* check if we need to notify the user about this modification */
            ids.rulenum = can_rule.rulenum;
            ids.tuple_id = can_rule.tuple.id;
            if (list_search_node(&can_rules_list, &ids)) {
                sentry_debug("can rulenum %d tuple_id %d was already handled\n", ids.rulenum, ids.tuple_id);
                continue;
            } else {
                rule_ids *new_ids = malloc(sizeof(rule_ids));
                new_ids->rulenum = can_rule.rulenum;
                new_ids->tuple_id = can_rule.tuple.id;
                list_append(&can_rules_list, new_ids);
                cb(SENTRY_ENTRY_CAN, SENTRY_OP_MODIFY, &can_rule);
            }
        }
        sr_free_values(values, count);
    } else {
        /* need to update only single tuple */
        ret = sscanf(xpath, CAN_TUPLEID_XPATH_FORMAT"/%s", &rulenum, &tuple_id, param);
        if (ret != 3) {
            sentry_error("failed to get updated param info\n");
            return SENTRY_ERR;
        }

        snprintf(rule_xpath, XPATH_MAX_LEN, CAN_TUPLEID_XPATH_FORMAT, rulenum, tuple_id);
        if (can_rule_create(&can_rule,  sess, rule_xpath) != SENTRY_OK) {
            sentry_error("failed to create ip rule from %s\n", rule_xpath);
            return SENTRY_ERR;
        }
        
        /* check if we need to notify the user about this modification */
        ids.rulenum = can_rule.rulenum;
        ids.tuple_id = can_rule.tuple.id;
        if (list_search_node(&can_rules_list, &ids)) {
            sentry_debug("can rulenum %d tuple_id %d was already handled\n", ids.rulenum, ids.tuple_id);
            return SENTRY_ERR;
        } else {
            rule_ids *new_ids = malloc(sizeof(rule_ids));
            new_ids->rulenum = can_rule.rulenum;
            new_ids->tuple_id = can_rule.tuple.id;
            list_append(&can_rules_list, new_ids);
            cb(SENTRY_ENTRY_CAN, SENTRY_OP_MODIFY, &can_rule);
        }
    }

    return SENTRY_OK;
}
