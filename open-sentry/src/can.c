#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include "list.h"
#include "action_module.h"
#include "can_module.h"
#include "can_drv_filter_common.h"
#include "open_sentry.h"

#define CAN_DRV_FILTER_ATTR_DEV_MASK        1<<CAN_DRV_FILTER_ATTR_DEV
#define CAN_DRV_FILTER_ATTR_MSG_ID_MASK     1<<CAN_DRV_FILTER_ATTR_MSG_ID
#define CAN_DRV_FILTER_ATTR_DIR_MASK        1<<CAN_DRV_FILTER_ATTR_DIR
#define CAN_DRV_FILTER_ATTR_LOG_MASK        1<<CAN_DRV_FILTER_ATTR_LOG
#define CAN_DRV_FILTER_ATTR_LOG_STRING_MASK 1<<CAN_DRV_FILTER_ATTR_LOG_STRING
#define CAN_DRV_FILTER_ATTR_PROG_MASK       1<<CAN_DRV_FILTER_ATTR_PROG
#define CAN_DRV_FILTER_ATTR_USER_MASK       1<<CAN_DRV_FILTER_ATTR_USER
#define CAN_DRV_FILTER_ATTR_RATE_MASK       1<<CAN_DRV_FILTER_ATTR_RATE
#define CAN_DRV_FILTER_ATTR_ACTION_MASK     1<<CAN_DRV_FILTER_ATTR_ACTION

#define CAN_DRV_FILTER_ATTR_ALL_MASK        (CAN_DRV_FILTER_ATTR_DEV_MASK | \
                                             CAN_DRV_FILTER_ATTR_MSG_ID_MASK | \
                                             CAN_DRV_FILTER_ATTR_DIR_MASK | \
                                             CAN_DRV_FILTER_ATTR_LOG_MASK | \
                                             CAN_DRV_FILTER_ATTR_LOG_STRING_MASK | \
                                             CAN_DRV_FILTER_ATTR_PROG_MASK | \
                                             CAN_DRV_FILTER_ATTR_USER_MASK | \
                                             CAN_DRV_FILTER_ATTR_RATE_MASK | \
                                             CAN_DRV_FILTER_ATTR_ACTION_MASK)

#define CAN_DRV_FILTER_ACT_MODIFIED_MASK    (CAN_DRV_FILTER_ATTR_DEV_MASK | \
                                             CAN_DRV_FILTER_ATTR_MSG_ID_MASK | \
                                             CAN_DRV_FILTER_ATTR_DIR_MASK | \
                                             CAN_DRV_FILTER_ATTR_LOG_MASK | \
                                             CAN_DRV_FILTER_ATTR_LOG_STRING_MASK | \
                                             CAN_DRV_FILTER_ATTR_ACTION_MASK)

/* global list of can rules */
static list_t can_rules_list;

/* auxiliary struct that help to maintain the can rules
 * the list above will contain can_rule structs.
 * we maintain it in a list mainly because the relation with the action.
 * action may change in runtime and we need need a way to update the rule */
typedef struct {
    unsigned short   rulenum;
    unsigned int     tuple_id;
    unsigned int     msg_id;
    unsigned int     direction;
    action_t        *action;
} can_rule;

/* can logger thread */
static pthread_t can_logger_thread_id = 0;

/* pipe for comm between the main process and can_logger */
int can_pipe_fds[2];

/* global nl_socket. connection to kernel can filter module */
static struct nl_sock *sock;
static int id;

static char* sentry_can_severity_str[LOG_SEVERITY_TOTAL] = {
    "NONE",
    "CRITICAL",
    "ERROR",
    "WARNING",
    "INFO",
    "DEBUG",
};

/***********************************************************************
 * function:    can_rules_constract_can_rule
 * description: 
 * in param:    
 * return:      SENTRY_ERR/SENTRY_OK
 **********************************************************************/
static int constract_can_command(can_rule_t *can_rule,
                                 int          op,
                                 int          attr_mask,
                                 action_t    *action)
{
    int ret = SENTRY_OK;
    unsigned char cmd;
    struct nl_msg *msg = NULL;

    if (!sock) {
        sentry_error("no can socket\n");
        return SENTRY_ERR;
    }

    switch (op) {
    case SENTRY_OP_DELETE:
        cmd = CAN_DRV_FILTER_CMD_DEL;
        break;
    case SENTRY_OP_CREATE:
        cmd = CAN_DRV_FILTER_CMD_ADD;
        break;
    case SENTRY_OP_MODIFY:
        cmd = CAN_DRV_FILTER_CMD_MOD;
        break;
    default:
        return SENTRY_ERR;
    }
    
    msg = nlmsg_alloc();
    if (!msg) {
        sentry_error("nlmsg_alloc failed\n");
        return SENTRY_ERR;
    }

    if (!genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, id, 0, 0, cmd,
            CAN_DRV_FILTER_VERSION_NR)) {
        sentry_error("genlmsg_put failed\n");
        goto err;
    }

    // TODO: get the device name from configuration
    if (attr_mask & CAN_DRV_FILTER_ATTR_DEV_MASK) {
        /* TODO: device need to be configurable */
        ret = nla_put_string(msg, CAN_DRV_FILTER_ATTR_DEV, "");
        if (ret < 0) {
            sentry_error("genl_ctrl_resolve failed: %s\n", nl_geterror(ret));
            goto err;
        }
    }

    if (attr_mask & CAN_DRV_FILTER_ATTR_MSG_ID_MASK) {
        /* check if this is a default filter */
        if (can_rule->tuple.msg_id == (unsigned int)(-1)) {
            ret = nla_put_u8(msg, CAN_DRV_FILTER_ATTR_DEFAULT, 1);
            if (ret < 0) {
                sentry_error("nla_put_u8 failed: %s\n", nl_geterror(ret));
                goto err;
            }
        } else {
            ret = nla_put_u32(msg, CAN_DRV_FILTER_ATTR_MSG_ID, can_rule->tuple.msg_id);
            if (ret < 0) {
                sentry_error("nla_put_u32 failed: %s\n", nl_geterror(ret));
                goto err;
            }
        }
    }

    if (attr_mask & CAN_DRV_FILTER_ATTR_DIR_MASK) {
        if (can_rule->tuple.direction == SENTRY_DIR_IN)
            ret = nla_put_u8(msg, CAN_DRV_FILTER_ATTR_DIR,
                CAN_DRV_FILTER_DIR_RX);
        else if (can_rule->tuple.direction == SENTRY_DIR_OUT)
            ret = nla_put_u8(msg, CAN_DRV_FILTER_ATTR_DIR,
                CAN_DRV_FILTER_DIR_TX);
        else if (can_rule->tuple.direction == SENTRY_DIR_BOTH)
            ret = nla_put_u8(msg, CAN_DRV_FILTER_ATTR_DIR,
                CAN_DRV_FILTER_DIR_BOTH);

        if (ret < 0) {
            sentry_error("nla_put_u8 failed: %s\n", nl_geterror(ret));
            goto err;
        }
    }

    if (attr_mask & CAN_DRV_FILTER_ATTR_LOG_MASK) {
        ret = nla_put_u8(msg, CAN_DRV_FILTER_ATTR_LOG, action->log_severity);
        if (ret < 0) {
            sentry_error("nla_put_u8 failed: %s\n", nl_geterror(ret));
            goto err;
        }
    }

    if (attr_mask & CAN_DRV_FILTER_ATTR_LOG_STRING_MASK) {
        char can_cef[CAN_DRV_STR_SIZE];

        snprintf(can_cef, CAN_DRV_STR_SIZE, "CEF:0|%s|%s|%s|300|CAN-EVENT|%s|",
            DEVICE_VENDOR, DEVICE_PRODUCT, DEVICE_VERSION,
            sentry_can_severity_str[action->log_severity]);

        ret = nla_put_string(msg, CAN_DRV_FILTER_ATTR_LOG_STRING, can_cef);
        if (ret < 0) {
            sentry_error("nla_put_string failed: %s\n", nl_geterror(ret));
            goto err;
        }
    }

    if (attr_mask & CAN_DRV_FILTER_ATTR_ACTION_MASK) {
        if (action->action == ACTION_DROP)
            ret = nla_put_u8(msg, CAN_DRV_FILTER_ATTR_ACTION, CAN_DRV_FILTER_ACT_DROP);
        else
            ret = nla_put_u8(msg, CAN_DRV_FILTER_ATTR_ACTION, CAN_DRV_FILTER_ACT_ALLOW);
        if (ret < 0) {
            sentry_error("nla_put_u8 failed: %s\n", nl_geterror(ret));
            goto err;
        }
    }

    if (attr_mask & CAN_DRV_FILTER_ATTR_USER_MASK) {
        ret = nla_put_string(msg, CAN_DRV_FILTER_ATTR_USER,
            can_rule->tuple.user);
        if (ret < 0) {
            sentry_error("nla_put_string failed: %s\n", nl_geterror(ret));
            goto err;
        }
    }

    if (attr_mask & CAN_DRV_FILTER_ATTR_PROG_MASK) {
        ret = nla_put_string(msg, CAN_DRV_FILTER_ATTR_PROG, can_rule->tuple.program);
        if (ret < 0) {
            sentry_error("nla_put_string failed: %s\n", nl_geterror(ret));
            goto err;
        }
    }

    if (attr_mask & CAN_DRV_FILTER_ATTR_RATE_MASK) {
        ret = nla_put_u32(msg, CAN_DRV_FILTER_ATTR_RATE,
            can_rule->tuple.max_rate);
        if (ret < 0) {
            sentry_error("nla_put_u32 failed: %s\n", nl_geterror(ret));
            goto err;
        }
    }

    ret = nl_send_auto(sock, msg);
    if (ret < 0) {
        sentry_error("nl_send_auto failed: %s\n", nl_geterror(ret));
        goto err;
    }

    nlmsg_free(msg);
    return SENTRY_OK;

err:
    nlmsg_free(msg);

    return SENTRY_ERR;
}

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
    can_rule *search_ptr = (can_rule*)data;
    can_rule *candidate_ptr = (can_rule*)candidate;

    if (search_ptr->rulenum == candidate_ptr->rulenum &&
            search_ptr->tuple_id == candidate_ptr->tuple_id)
        return true;

    return false;
}

/***********************************************************************
 * function:    can_log_parse
 * description: 
 * in param:    
 * return:      
 **********************************************************************/
static int can_log_parse(struct nl_msg* msg, void* arg)
{
    struct nlmsghdr *hdr = nlmsg_hdr(msg);
    struct nlattr * log_attr = NULL;
    int payloadlen = nlmsg_datalen(hdr);
    void *data = nlmsg_data(hdr);
    char *log;

    payloadlen -= GENL_HDRLEN;
    data += GENL_HDRLEN;
    log_attr = data;

    while (payloadlen > 0) {
        log = nla_data(log_attr);
        log_event(log);
        log_attr = nla_next(log_attr, &payloadlen);
    }

    return 0;
}

/***********************************************************************
 * function:    can_logger_task
 * description: 
 * in param:    
 * return:      
 **********************************************************************/
static void* can_logger_task(void *data)
{
    int ret= 0, fd = 0, group = 0;
    fd_set rfds;

    if (!sock) {
        sentry_error("no netlink socket\n");
        return NULL;
    }

    ret = nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM,
        can_log_parse, NULL);
    if (ret < 0 ) {
        sentry_error("nl_socket_modify_cb failed: %s\n", nl_geterror(ret));
        return NULL;
    }

    group = genl_ctrl_resolve_grp(sock, CAN_DRV_FILTER_NAME,
        CAN_DRV_FILTER_MCAST_GROUP_NAME);
    if (group < 0 ) {
        sentry_error("genl_ctrl_resolve_grp failed: %s\n", nl_geterror(group));
        return NULL;
    }

    ret = nl_socket_add_membership(sock, group);
    if (ret < 0) {
        sentry_error("nl_socket_add_membership failed: %s\n", nl_geterror(ret));
        return NULL;
    }

    fd = nl_socket_get_fd(sock);
    while (true) {
        FD_ZERO(&rfds);

        /* watch for netlink event or on the pipe (i.e. exit) without timeout */
        FD_SET(fd, &rfds);
        FD_SET(can_pipe_fds[0], &rfds);

        ret = select((MAX(fd,can_pipe_fds[0]) + 1), &rfds, NULL, NULL, NULL);
        if (ret > 0) {
            if (FD_ISSET(can_pipe_fds[0] , &rfds)) {
                sentry_debug("can_logger_task exit ...\n");
                break;
            }

            if ((ret = nl_recvmsgs_default(sock)) < 0)
                sentry_error("nl_recvmsgs_default %s\n", nl_geterror(ret));
        } else if (ret < 0)
            sentry_error("select failed: %s\n", strerror(errno));
    }

    pthread_detach(pthread_self());

    return NULL;
}

/***********************************************************************
 * function:    can_init
 * description: init the can module
 * return:      SENTRY_OK/SENTRY_ERR
 **********************************************************************/
int can_init(void)
{
    int ret = 0;

    sock = nl_socket_alloc();
    if (!sock) {
        sentry_error("Failed to allocate netlink socket\n");
        return SENTRY_ERR;
    }

    if ((ret = genl_connect(sock))) {
        sentry_error("genl_connect failed: %s\n", nl_geterror(ret));
        goto err;
    }

    id = genl_ctrl_resolve(sock, CAN_DRV_FILTER_NAME);
    if (id < 0) {
        sentry_error("genl_ctrl_resolve failed: %s\n", nl_geterror(id));
        goto err;
    }

    nl_socket_disable_seq_check(sock);
    nl_socket_set_passcred(sock, 0);

    if (pipe(can_pipe_fds) < 0){
        sentry_error("pipe failed %s\n", strerror(errno));
        goto err;
    }

    if (pthread_create(&can_logger_thread_id, NULL, &can_logger_task, NULL) != 0) {
        sentry_error("pthread_create failed: %s\n", strerror(errno));
        can_logger_thread_id = 0;
        goto err;
    }

    list_init(&can_rules_list, can_rule_search_cb, NULL, NULL);

    return SENTRY_OK;

err:
    nl_socket_free(sock);
    sock = NULL;
    return SENTRY_ERR;
}

/***********************************************************************
 * function:    can_deinit
 * description: deinit the can module
 * return:      SENTRY_OK/SENTRY_ERR
 **********************************************************************/
void can_deinit(void)
{
    node_t *ptr = can_rules_list.head;
    can_rule *can_rule_ptr;
    can_rule_t rule;

    while(ptr) {
        can_rule_ptr = list_remove_node(&can_rules_list, ptr);
        if (can_rule_ptr) {
            rule.tuple.msg_id = can_rule_ptr->msg_id;
            rule.tuple.direction = can_rule_ptr->direction;
            constract_can_command(&rule, SENTRY_OP_DELETE,
                (CAN_DRV_FILTER_ATTR_MSG_ID_MASK | CAN_DRV_FILTER_ATTR_DIR_MASK), NULL);
            free(can_rule_ptr);
        }
        ptr = can_rules_list.head;
    }

    can_enable(false);

    if (write(can_pipe_fds[1], "STOP", 4) < 0)
        sentry_error("write to pipe failed: %s\n", strerror(errno));

    if (can_logger_thread_id)
        pthread_join(can_logger_thread_id, NULL);

    if (sock) {
        nl_close(sock);
        nl_socket_free(sock);
    }

    memset(&rule, 0, sizeof(can_rule_t));
}

/***********************************************************************
 * function:    action_search_by_name
 * description: search for an action in the list by name.
 * in param:    char *name - the action name.
 * return:      action_t*
 **********************************************************************/
static can_rule* can_rule_search_by_ids(unsigned short rulenum, unsigned int tuple_id)
{
    node_t *candidate = NULL;
    can_rule ids = {
        .rulenum = rulenum,
        .tuple_id = tuple_id,
    };

    candidate = list_search_node(&can_rules_list, &ids);
    if (!candidate)
        return NULL;

    return (can_rule*)candidate->data;
}



/***********************************************************************
 * function:    can_rule_create
 * description: add new can rule to can_rules_list
 * in param:    action_t *new_action
 * return:      SENTRY_OK/SENTRY_ERR
 **********************************************************************/
static int can_rule_create(can_rule_t *rule)
{
    can_rule *new_rule = NULL;

    if (!rule)
        return SENTRY_ERR;

    new_rule = can_rule_search_by_ids(rule->rulenum, rule->tuple.id);
    if (new_rule) {
        sentry_error("can rule [%d/%d] already exist\n", rule->rulenum, rule->tuple.id);
        return SENTRY_ERR;
    }

    /* alocate new action_t struct */
    new_rule = malloc(sizeof(can_rule));
    if (!new_rule) {
        sentry_error("cant allocate memory for new can rule\n");
        return SENTRY_ERR;
    }

    memset(new_rule, 0, sizeof(can_rule));
    new_rule->tuple_id = rule->tuple.id;
    new_rule->rulenum = rule->rulenum;
    new_rule->msg_id = rule->tuple.msg_id;
    new_rule->direction = rule->tuple.direction;
    new_rule->action = action_search_by_name(rule->action_name);
    if (!new_rule->action) {
        sentry_error("failed to find action %s\n", rule->action_name);
        free(new_rule);
        return SENTRY_ERR;
    }

    /* add the new action to list */
    if (list_append(&can_rules_list, new_rule) == NULL) {
        sentry_error("failed to add the new can rule to list\n");
        free(new_rule);
        return SENTRY_ERR;
    }

    constract_can_command(rule, SENTRY_OP_CREATE,
        CAN_DRV_FILTER_ATTR_ALL_MASK, new_rule->action);

    sentry_debug("created can rule [%d,%d]\n", rule->rulenum, rule->tuple.id);

    return SENTRY_OK;
}

/***********************************************************************
 * function:    can_rule_delete
 * description: delete can rule from the list. search by ref can_rule_t
 * in param:    action_t *
 * return:      SENTRY_OK/SENTRY_ERR
 **********************************************************************/
static int can_rule_delete(can_rule_t *rule)
{
    node_t *candidate = NULL;
    can_rule *del_rule = NULL;
    can_rule ids = {
        .rulenum = rule->rulenum,
        .tuple_id = rule->tuple.id,
    };

    if (!rule)
        return SENTRY_ERR;

    /* remove from the list */
    candidate = list_search_node(&can_rules_list, &ids);
    if (!candidate) {
        sentry_error("couldn't find can rule [%d,%d]\n", rule->rulenum, rule->tuple.id);
        return SENTRY_ERR;
    }

    if ((del_rule = list_remove_node(&can_rules_list, candidate)) == NULL) {
        sentry_error("failed to remove node\n");
        return SENTRY_ERR;
    }

    /* the delete can_rule_t does not contain the msg_is nor the direction */
    rule->tuple.msg_id = del_rule->msg_id;
    rule->tuple.direction = del_rule->direction;
    /* remove the rule from kernel can filter module */
    constract_can_command(rule, SENTRY_OP_DELETE,
            (CAN_DRV_FILTER_ATTR_MSG_ID_MASK | CAN_DRV_FILTER_ATTR_DIR_MASK),
            NULL);

    free(del_rule);

    sentry_debug("deleted can rule [%d,%d]\n", rule->rulenum, rule->tuple.id);

    return SENTRY_OK;
}

/***********************************************************************
 * function:    can_rule_modify
 * description: modify can rule on the list. search by ref can_rule_t
 * in param:    action_t *
 * return:      SENTRY_OK/SENTRY_ERR
 **********************************************************************/
static int can_rule_modify(can_rule_t *rule)
{
    can_rule *mod_rule = NULL;

    if (!rule)
        return SENTRY_ERR;

    mod_rule = can_rule_search_by_ids(rule->rulenum, rule->tuple.id);
    if (!mod_rule) {
        sentry_error("couldn't find can rule [%d,%d]\n", rule->rulenum, rule->tuple.id);
        return SENTRY_ERR;
    }

    /* incase the msg_id is different we dont actually modify but create
     * new rule and delete the prev */
    if (mod_rule->msg_id != rule->tuple.msg_id) {
        can_rule_t rule_tmp;

        memset(&rule_tmp, 0, sizeof(can_rule_t));
        rule_tmp.tuple.id = rule->tuple.id;
        rule_tmp.rulenum = rule->rulenum;
        rule_tmp.tuple.msg_id = mod_rule->msg_id;
        rule_tmp.tuple.direction = mod_rule->direction;
        if (can_rule_delete(&rule_tmp) != SENTRY_OK) {
            sentry_error("failed to delete the new rule\n");
            return SENTRY_ERR;
        }
        if (can_rule_create(rule) != SENTRY_OK) {
            sentry_error("failed to create the new rule\n");
            return SENTRY_ERR;
        }

        sentry_debug("modified can rule [%d,%d]\n", rule->rulenum, rule->tuple.id);

        return SENTRY_OK;
    }

    mod_rule->tuple_id = rule->tuple.id;
    mod_rule->rulenum = rule->rulenum;
    mod_rule->msg_id = rule->tuple.msg_id;
    mod_rule->direction = rule->tuple.direction;
    mod_rule->action = action_search_by_name(rule->action_name);
    if (!mod_rule->action) {
        sentry_error("failed to find action %s\n", rule->action_name);
        return SENTRY_ERR;
    }

    /* modify the rule in the kernel can filter module */
    constract_can_command(rule, SENTRY_OP_MODIFY,
            CAN_DRV_FILTER_ATTR_ALL_MASK, mod_rule->action);

    sentry_debug("modified can rule [%d,%d]\n", rule->rulenum, rule->tuple.id);

    return SENTRY_OK;
}

/***********************************************************************
 * function:    action_handle_event
 * description: handle action event
 * in param:    action_t *
 * return:      SENTRY_OK/SENTRY_ERR
 **********************************************************************/
int can_handle_event(int op, can_rule_t *rule)
{
    switch (op) {
    case SENTRY_OP_CREATE:
        return can_rule_create(rule);
    case SENTRY_OP_DELETE:
        return can_rule_delete(rule);
    case SENTRY_OP_MODIFY:
        return can_rule_modify(rule);
    default:
        return SENTRY_ERR;
    }
}

/***********************************************************************
 * function:    can_enable
 * description: enable disable the kernel can filter
 * in param:    bool enable
 * return:      SENTRY_OK/SENTRY_ERR
 **********************************************************************/
int can_enable(bool enable)
{
    int ret = SENTRY_OK;
    unsigned char cmd;
    struct nl_msg *msg = NULL;

    if (!sock) {
        sentry_error("no can socket\n");
        return SENTRY_ERR;
    }

    if (enable)
        cmd = CAN_DRV_FILTER_CMD_ENABLE;
    else
        cmd = CAN_DRV_FILTER_CMD_DISABLE;
    
    msg = nlmsg_alloc();
    if (!msg) {
        sentry_error("nlmsg_alloc failed\n");
        return SENTRY_ERR;
    }

    if (!genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, id, 0, 0, cmd,
            CAN_DRV_FILTER_VERSION_NR)) {
        sentry_error("genlmsg_put failed\n");
        goto err;
    }

    ret = nl_send_auto(sock, msg);
    if (ret < 0) {
        sentry_error("nl_send_auto failed: %s\n", nl_geterror(ret));
        goto err;
    }

    nlmsg_free(msg);
    return SENTRY_OK;

err:
    nlmsg_free(msg);

    return SENTRY_ERR;
}
