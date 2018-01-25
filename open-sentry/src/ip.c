#include <string.h>
#include <stdbool.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <libnetfilter_log/libnetfilter_log.h>
#include <sys/time.h>
#include "list.h"
#include "action_module.h"
#include "ip_module.h"
#include "open_sentry.h"

#define IPTABLES_VER(x, y, z) (((x & 0xFF) << 16) | ((y & 0xFF) << 8) | (z & 0xFF))
static int iptables_ver = 0;

/* global list of ip rules */
static list_t ip_rules_list;

/* auxiliary struct that help to maintain the ip rules
 * the list above will contain ip_rule structs.
 * we maintain it in a list mainly because the relation with the action.
 * action may change in runtime and we need need a way to update the rule */
typedef struct {
    unsigned short   rulenum;
    unsigned int     tuple_id;
    unsigned int     direction;
    action_t        *action;
} ip_rule;

/* ip logger thread */
static pthread_t ip_logger_thread_id = 0;

/* pipe for comm between the main process and ip_logger */
int ip_pipe_fds[2];

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
    ip_rule *search_ptr = (ip_rule*)data;
    ip_rule *candidate_ptr = (ip_rule*)candidate;

    if ((search_ptr->rulenum == candidate_ptr->rulenum) &&
            (search_ptr->tuple_id == candidate_ptr->tuple_id))
        return true;

    return false;
}

/***********************************************************************
 * function:    ip_rule_compare_cb
 * description: compare 2 ip_rules_t * based on rulenum and tuple.id.
 *              return the state of a compared to b.
 * in param:    void* a.
 *              void* b.
 * return:      NODE_CMP_SMALLER/EQUAL/BIGGER,.
 **********************************************************************/
int ip_rule_compare_cb(void* a, void* b)
{
    ip_rule *ip_rule_a = (ip_rule*)a;
    ip_rule *ip_rule_b = (ip_rule*)b;

    unsigned short rulenum_a = ip_rule_a->rulenum;
    unsigned short rulenum_b = ip_rule_b->rulenum;
    unsigned int tuple_id_a = ip_rule_a->tuple_id;
    unsigned int tuple_id_b = ip_rule_b->tuple_id;

    if (rulenum_a > rulenum_b)
        return NODE_CMP_BIGGER;
    else if (rulenum_a < rulenum_b)
        return NODE_CMP_SMALLER;
    else {
        if (tuple_id_a > tuple_id_b)
            return NODE_CMP_BIGGER;
        else if (tuple_id_a < tuple_id_b)
            return NODE_CMP_SMALLER;
        else
            return NODE_CMP_EQUAL;
    }
}


/***********************************************************************
 * function:    ip_rules_get_idxs
 * description: this is an auxiliary function to help when working with
 *              the iptables. the iptables are index based so incase we
 *              need to delete/modifiy a rule, this function will tell
 *              what is the index of the rule in INPUT & OUTPUT tables
 * in param:    ip_rule *rule. the rule we need to find its indexes.
 * out pram:    int *ipt_out_idx. the INPUT table index
 *              int *ipt_in_idx. the OUTPUT table index
 * return:      SENTRY_OK(rule found)/SENTRY_ERR(not found)
 **********************************************************************/
static int ip_rules_get_idxs(ip_rule *rule, int *ipt_out_idx, int *ipt_in_idx)
{
    node_t *ptr = ip_rules_list.head;
    ip_rule *ip_rule_p = NULL;
    int in_idx = 0, out_idx = 0;

    while(ptr) {
        ip_rule_p = (ip_rule*)ptr->data;
        if (!ip_rule_p) {
            ptr = ptr->next;
            continue;
        }

        if (ip_rule_p->direction & SENTRY_DIR_OUT)
            out_idx++;

        if (ip_rule_p->direction & SENTRY_DIR_IN)
            in_idx++;

        if ((ip_rule_p->rulenum == rule->rulenum) &&
            (ip_rule_p->tuple_id == rule->tuple_id)) {
            break;
        }

        ptr = ptr->next;
    }

    if (!ptr) {
        *ipt_out_idx = 0;
        *ipt_in_idx = 0;
        return SENTRY_ERR;
    }

    sentry_debug("out_idx = %d, in_idx = %d\n", out_idx, in_idx);
    *ipt_out_idx = out_idx;
    *ipt_in_idx = in_idx;

    return SENTRY_OK;
}

/* some global string defs to ease the iptables cmdline creation */
static char *iptables_ops[SENTRY_OP_TOTAL] = {
    "-I",
    "-D",
    "-R",
};

static char *sentry_ip_severity_str[LOG_SEVERITY_TOTAL] = {
    "NONE",
    "CRITICAL",
    "ERROR",
    "WARNING",
    "INFO",
    "DEBUG",
};

static char *sentry_ip_log_chains[LOG_SEVERITY_TOTAL] = {
    "",
    "sentry_log_critical",
    "sentry_log_error",
    "sentry_log_warning",
    "sentry_log_info",
    "sentry_log_debug",
};

static char *sentry_ip_log_drop_chains[LOG_SEVERITY_TOTAL] = {
    "",
    "sentry_log_drop_critical",
    "sentry_log_drop_error",
    "sentry_log_drop_warning",
    "sentry_log_drop_info",
    "sentry_log_drop_debug",
};

static char *default_iptables_cmds_size[] = {
    // allow local traffic
    "INPUT -i lo -j ACCEPT",
    "OUTPUT -o lo -j ACCEPT",

    // allow traffic that belongs to established connections, or new valid traffic
    "INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",

    // SYN scans protection
    "INPUT -p tcp -m recent --update --rsource --seconds 30 --name TCP-PORTSCAN -j REJECT --reject-with tcp-reset",
    // UDP scans protection
    "INPUT -p udp -m recent --update --rsource --seconds 30 --name UDP-PORTSCAN -j REJECT --reject-with icmp-port-unreachable",

    // Droping all invalid packets
    "INPUT -m conntrack --ctstate INVALID -j DROP",

    // notify of new TCP/UDP conenction
    "INPUT -p udp -m conntrack --ctstate NEW -j NFLOG --nflog-size 64 --nflog-prefix \"level=NewUDPConn act=log\"",
    "INPUT -p tcp -m conntrack --ctstate NEW -j NFLOG --nflog-size 64 --nflog-prefix \"level=NewTCPConn act=log\"",
    "OUTPUT -p udp -m conntrack --ctstate NEW -j NFLOG --nflog-size 64 --nflog-prefix \"level=NewUDPConn act=log\"",
    "OUTPUT -p tcp -m conntrack --ctstate NEW -j NFLOG --nflog-size 64 --nflog-prefix \"level=NewTCPConn act=log\"",

    // accept incoming TCP/UDP requests for a DNS server (port 53):
    "INPUT -p tcp --dport 53 -j ACCEPT",
    "INPUT -p udp --dport 53 -j ACCEPT",
    "INPUT -p tcp --dport 5353 -j ACCEPT",
    "INPUT -p udp --dport 5353 -j ACCEPT",

    "INPUT -p tcp --dport 22 -j ACCEPT",

    // SYN scans detection
    "PORTSCAN_REJECT -p tcp -j NFLOG --nflog-size 64 --nflog-prefix \"level=ERROR-PS-TCP act=reject\"",
    "PORTSCAN_REJECT -p tcp -j REJECT --reject-with tcp-reset",
    "INPUT -p tcp -m recent --set --rsource --name TCP-PORTSCAN -j PORTSCAN_REJECT",

    // UDP scans detection
    "PORTSCAN_REJECT -p udp -j NFLOG --nflog-size 64 --nflog-prefix \"level=ERROR-PS-UDP act=reject\"",
    "PORTSCAN_REJECT -p udp -j REJECT --reject-with icmp-port-unreachable",
    "INPUT -p udp -m recent --set --rsource --name UDP-PORTSCAN -j PORTSCAN_REJECT",
};

static char *default_iptables_cmds_range[] = {
    // allow local traffic
    "INPUT -i lo -j ACCEPT",
    "OUTPUT -o lo -j ACCEPT",

    // allow traffic that belongs to established connections, or new valid traffic
    "INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",

    // SYN scans protection
    "INPUT -p tcp -m recent --update --rsource --seconds 30 --name TCP-PORTSCAN -j REJECT --reject-with tcp-reset",
    // UDP scans protection
    "INPUT -p udp -m recent --update --rsource --seconds 30 --name UDP-PORTSCAN -j REJECT --reject-with icmp-port-unreachable",

    // Droping all invalid packets
    "INPUT -m conntrack --ctstate INVALID -j DROP",

    // notify of new TCP/UDP conenction
    "INPUT -p udp -m conntrack --ctstate NEW -j NFLOG --nflog-range  64 --nflog-prefix \"level=NewUDPConn act=log\"",
    "INPUT -p tcp -m conntrack --ctstate NEW -j NFLOG --nflog-range  64 --nflog-prefix \"level=NewTCPConn act=log\"",
    "OUTPUT -p udp -m conntrack --ctstate NEW -j NFLOG --nflog-range  64 --nflog-prefix \"level=NewUDPConn act=log\"",
    "OUTPUT -p tcp -m conntrack --ctstate NEW -j NFLOG --nflog-range  64 --nflog-prefix \"level=NewTCPConn act=log\"",

    // accept incoming TCP/UDP requests for a DNS server (port 53):
    "INPUT -p tcp --dport 53 -j ACCEPT",
    "INPUT -p udp --dport 53 -j ACCEPT",
    "INPUT -p tcp --dport 5353 -j ACCEPT",
    "INPUT -p udp --dport 5353 -j ACCEPT",

    "INPUT -p tcp --dport 22 -j ACCEPT",

    // SYN scans detection
    "PORTSCAN_REJECT -p tcp -j NFLOG --nflog-range  64 --nflog-prefix \"level=ERROR-PS-TCP act=reject\"",
    "PORTSCAN_REJECT -p tcp -j REJECT --reject-with tcp-reset",
    "INPUT -p tcp -m recent --set --rsource --name TCP-PORTSCAN -j PORTSCAN_REJECT",

    // UDP scans detection
    "PORTSCAN_REJECT -p udp -j NFLOG --nflog-range  64 --nflog-prefix \"level=ERROR-PS-UDP act=reject\"",
    "PORTSCAN_REJECT -p udp -j REJECT --reject-with icmp-port-unreachable",
    "INPUT -p udp -m recent --set --rsource --name UDP-PORTSCAN -j PORTSCAN_REJECT",
};

/***********************************************************************
 * function:    constract_sentry_ipchains
 * description: this fucntion create/delete  per severity-log 2 chains
 *              in the iptables. one for logging and the other logging and
 *              dropping. based on the ip rule action, the relevant
 *              action/logging will take place. 
 * in param:    bool add. true - add chains, false - delete chains.
 * return:      void.
 **********************************************************************/
static void constract_sentry_ipchains(bool add)
{
    int i = 0;
    char cmd[STR_MAX_SIZE];

    for (i=(LOG_SEVERITY_NONE+1); i<LOG_SEVERITY_TOTAL; i++) {
        /* TODO: add "-m limit --limit 100/minute" */

        if (add) {
            /* create the log chain */
            snprintf(cmd, STR_MAX_SIZE, "iptables -N %s", sentry_ip_log_chains[i]);
            if (system(cmd) < 0)
                sentry_error("system failed for %s\n", cmd);

            snprintf(cmd, STR_MAX_SIZE, "iptables -N %s",
                sentry_ip_log_drop_chains[i]);
            if (system(cmd) < 0)
                sentry_error("system failed for %s\n", cmd);

        } else {
            /* flush all rules from log chain */
            snprintf(cmd, STR_MAX_SIZE, "iptables -F %s",
                sentry_ip_log_chains[i]);
            if (system(cmd) < 0)
                sentry_error("system failed for %s\n", cmd);

            /* delete the log chain */
            snprintf(cmd, STR_MAX_SIZE, "iptables -X %s",
                sentry_ip_log_chains[i]);
            if (system(cmd) < 0)
                sentry_error("system failed for %s\n", cmd);

            /* flush all rules from log_drop chain */
            snprintf(cmd, STR_MAX_SIZE, "iptables -F %s",
                sentry_ip_log_drop_chains[i]);
            if (system(cmd) < 0)
                sentry_error("system failed for %s\n", cmd);

            /* delete the log_drop chain */
            snprintf(cmd, STR_MAX_SIZE, "iptables -X %s",
                sentry_ip_log_drop_chains[i]);
            if (system(cmd) < 0)
                sentry_error("system failed for %s\n", cmd);
        }
    }

    if (add) {
        if (system("iptables -N PORTSCAN_REJECT") < 0)
            sentry_error("system failed to create PORTSCAN_REJECT\n");
    } else {
        if (system("iptables -F PORTSCAN_REJECT") < 0)
            sentry_error("system failed to flush PORTSCAN_REJECT\n");
        if (system("iptables -X PORTSCAN_REJECT") < 0)
            sentry_error("system failed to delete PORTSCAN_REJECT\n");
    }
}

#define IP_TABLE_CMD_MAX_LEM    1024
static int rate_limit_index = 1;
/***********************************************************************
 * function:    compose_ip_rule
 * description: 
 * in param:    
 * return:      
 **********************************************************************/
static void compose_ip_rule(unsigned char  direction,
                            action_t      *action,
                            ip_rule_t    *ip_rule,
                            char          *cmd,
                            unsigned char  op,
                            int            idx)
{
    char port[ACTION_STR_SIZE], portocol[ACTION_STR_SIZE];
    char line[ACTION_STR_SIZE];
    char rate_limit[STR_MAX_SIZE];
    bool add_ports = false;
    int severity = 0;

    /* TODO: fix the cmd creation ... make sure no buffer overrun */
    snprintf(cmd, IP_TABLE_CMD_MAX_LEM, "iptables %s ", iptables_ops[op]);

    if (direction == SENTRY_DIR_IN)
        strcat(cmd, "INPUT ");
    else
        strcat(cmd, "OUTPUT ");

    if (idx) {
        snprintf(line, ACTION_STR_SIZE, "%d ", idx);
        strcat(cmd, line);
    }

    /* when we delete we can use the index only ... and
     * we dont have the actual params anymore */
    if (op == SENTRY_OP_DELETE)
        return;

    if ((ip_rule->tuple.srcaddr.s_addr == 0x100007F) &&
            (ip_rule->tuple.dstaddr.s_addr == 0x100007F)) {
        if (direction == SENTRY_DIR_IN)
            strcat(cmd, "-i lo ");
        else
            strcat(cmd, "-o lo ");
    }

    if ((ip_rule->tuple.srcaddr.s_addr != 0) &&
        (ip_rule->tuple.srcaddr.s_addr != 0x100007F) ) {
        strcat(cmd, "-s ");
        strcat(cmd, inet_ntoa(ip_rule->tuple.srcaddr));

        if (ip_rule->tuple.srcnetmask.s_addr != 0xFFFFFFFF) {
            strcat(cmd, "/");
            strcat(cmd, inet_ntoa(ip_rule->tuple.srcnetmask));
        }
        strcat(cmd, " ");
    }

    if ((ip_rule->tuple.dstaddr.s_addr != 0) &&
        (ip_rule->tuple.dstaddr.s_addr != 0x100007F) ) {
        strcat(cmd, "-d ");
        strcat(cmd, inet_ntoa(ip_rule->tuple.dstaddr));

        if (ip_rule->tuple.dstnetmask.s_addr != 0xFFFFFFFF) {
            strcat(cmd, "/");
            strcat(cmd, inet_ntoa(ip_rule->tuple.dstnetmask));
        }
        strcat(cmd, " ");
    }

    if (ip_rule->tuple.proto) {
        if (ip_rule->tuple.proto == IPPROTO_TCP) {
            /* TCP */
            add_ports = true;
            strcat(cmd, "-p tcp ");
        } else if (ip_rule->tuple.proto == IPPROTO_UDP) {
            /* UDP */
            add_ports = true;
            strcat(cmd, "-p udp ");
        } else {
            strcat(cmd, "-p ");
            snprintf(portocol, ACTION_STR_SIZE, "%d ", ip_rule->tuple.proto);
            strcat(cmd, portocol);
        }
    }

    if (add_ports) {
        if (ip_rule->tuple.dstport) {
            strcat(cmd, "--dport ");
            snprintf(port, ACTION_STR_SIZE, "%d ", ip_rule->tuple.dstport);
            strcat(cmd, port);
        }

        if (ip_rule->tuple.srcport) {
            strcat(cmd, "--sport ");
            snprintf(port, ACTION_STR_SIZE, "%d ", ip_rule->tuple.srcport);
            strcat(cmd, port);
        }
    }

    if (ip_rule->tuple.max_rate > 0) {
        snprintf(rate_limit, STR_MAX_SIZE,
            "--match hashlimit --hashlimit-name %d --hashlimit-above %db/s ",
            rate_limit_index, ip_rule->tuple.max_rate);
        strcat(cmd, rate_limit);
        rate_limit_index++;
    }

    severity = action->log_severity;
    strcat(cmd, "-j ");
    if (action->action == ACTION_ALLOW)
        if ((action->log_facility != LOG_NONE) && (severity > 0))
            strcat(cmd, sentry_ip_log_chains[severity]);
        else
            strcat(cmd, "ACCEPT");
    else
        if ((action->log_facility != LOG_NONE) && (severity > 0))
            strcat(cmd, sentry_ip_log_drop_chains[severity]);
        else
            strcat(cmd, "DROP");
}

/***********************************************************************
 * function:    constract_iptable_cmd
 * description: 
 * in param:    
 * return:      
 **********************************************************************/
static void constract_iptable_cmd(ip_rule_t     *ip_rule,
                                  unsigned char  op,
                                  action_t      *action,
                                  int            out_idx,
                                  int            in_idx)
{
    char cmd_in[IP_TABLE_CMD_MAX_LEM];
    char cmd_out[IP_TABLE_CMD_MAX_LEM];

    if (in_idx > 0) {
        memset(cmd_in, 0, IP_TABLE_CMD_MAX_LEM);
        compose_ip_rule(SENTRY_DIR_IN, action, ip_rule, cmd_in, op, in_idx);
        sentry_debug("%s\n", cmd_in);
        if (system(cmd_in) < 0)
            sentry_error("failed to apply in rule\n");
    }

    if (out_idx > 0) {
        memset(cmd_out, 0, IP_TABLE_CMD_MAX_LEM);
        compose_ip_rule(SENTRY_DIR_OUT, action, ip_rule, cmd_out, op, out_idx);
        sentry_debug("%s\n", cmd_out);
        if (system(cmd_out) < 0)
            sentry_error("failed to apply out rule\n");
    }
}

/***********************************************************************
 * function:    parse_msg
 * description: parse a received msg from NFLOG and build a string log
 *              that will be written to the log file.
 * in param:    struct nflog_g_handle *gh,
                struct nfgenmsg *nfmsg,
                struct nflog_data *nfa,
                void *data
 * return:      SENTRY_OK.
 **********************************************************************/
static const char *months[12] = {
	"Jan",
	"Fab",
	"Mar",
	"Apr",
	"May",
	"Jun",
	"Jul",
	"Aug",
	"Sep",
	"Oct",
	"Nov",
	"Dec",
};

#define LOG_MSG_SIZE    4096

static int parse_msg(struct nflog_g_handle *gh,
                     struct nfgenmsg *nfmsg,
                     struct nflog_data *nfa,
                     void *data)
{
    char log[LOG_MSG_SIZE];
    char *ptr = log, *str_ret = NULL;
    int len = 0, left = LOG_MSG_SIZE, ret = 0;
    char dev_name[IF_NAMESIZE];
    struct nfulnl_msg_packet_hw *hw = NULL;
    struct nfulnl_msg_packet_hdr *hdr = NULL;
    struct timeval tv;
    struct tm *logtime = NULL;
    char action[STR_MAX_SIZE];
    char log_level_str[STR_MAX_SIZE];

    /* get timestamp */
    ret = nflog_get_timestamp(nfa, &tv);
    if (ret)
        gettimeofday(&tv, NULL);

    logtime = gmtime(&tv.tv_sec);
    if (logtime) {
        len = snprintf(ptr, left, "%s %d %.2d:%.2d:%.2d:%.6ld",
            months[logtime->tm_mon], logtime->tm_mday, logtime->tm_hour,
            logtime->tm_min, logtime->tm_sec, tv.tv_usec);
        if (len <= 0)
            goto out;
        left -= len;
        ptr += len;
    }

    len = snprintf(ptr, left, " CEF:0|%s|%s|%s|200|IP-EVENT|",
            DEVICE_VENDOR, DEVICE_PRODUCT, DEVICE_VERSION);
    left -= len;
    ptr += len;
    
    /* set the log prefix */
    str_ret = nflog_get_prefix(nfa);
    if (str_ret) {
        ret = sscanf(str_ret,"level=%s act=%s", log_level_str, action);
        if (ret == 2) {
            if (strncmp(log_level_str, "New", 3) == 0)
                len = snprintf(ptr, left, "INFO| %s ", log_level_str);
            else
                len = snprintf(ptr, left, "%s| ", log_level_str);
            if (len <= 0)
                goto out;
            left -= len;
            ptr += len;
        }
    }

    /* get the packet direction */
    len = 0;
    ret = nflog_get_indev(nfa);
    if (ret) {
        if (if_indextoname(ret, dev_name))
            len = snprintf(ptr, left, "dir=RX dev=%s", dev_name);
    } else {
        ret = nflog_get_outdev(nfa);
        if (ret) {
            if (if_indextoname(ret, dev_name))
                len = snprintf(ptr, left, "dir=TX dev=%s", dev_name);
        }
    }
    if (len < 0)
        goto out;

    left -= len;
    ptr += len;

    /* get MAC address */
    hw = nflog_get_packet_hw(nfa);
    if (hw) {
        len = snprintf(ptr, left, " MAC=%02x:%02x:%02x:%02x:%02x:%02x",
                    hw->hw_addr[0],hw->hw_addr[1],hw->hw_addr[2],
                    hw->hw_addr[3],hw->hw_addr[4],hw->hw_addr[5]);
        if (len <= 0)
            goto out;
        left -= len;
        ptr += len;
    }

    /* get hw protocol */
    hdr = nflog_get_msg_packet_hdr(nfa);
    if (hdr) {
        struct iphdr *ip = NULL;
        struct sockaddr_in ipaddr = {0};
        uint16_t hw_protocol;

        ret = nflog_get_payload(nfa, (char**)&ip);
        if (ret < 0)
            goto out;

        hw_protocol = ntohs(hdr->hw_protocol);
        if (!hw_protocol) {
            if (ret >= (int)sizeof(struct iphdr) && ip->version == 4) {
                hw_protocol = ETH_P_IP;
            }
        }

        len = snprintf(ptr, left, " hwproto=0x%04X", hw_protocol);
        if (len <= 0)
            goto out;
        left -= len;
        ptr += len;

        
        if (hw_protocol == ETH_P_IP) {
            /* src addr */
            ipaddr.sin_addr.s_addr = ip->saddr;
            len = snprintf(ptr, left, " SRC=%s", inet_ntoa(ipaddr.sin_addr));
            if (len <= 0)
                goto out;
            left -= len;
            ptr += len;

            /* dst addr */
            ipaddr.sin_addr.s_addr = ip->daddr;
            len = snprintf(ptr, left, " DST=%s", inet_ntoa(ipaddr.sin_addr));
            if (len <= 0)
                goto out;
            left -= len;
            ptr += len;

            len = 0;
            /* tcp/udp */
            if (ip->protocol == IPPROTO_TCP) {
                struct tcphdr *tcp =
                    (struct tcphdr*)((unsigned int*)ip + ip->ihl);
                len = snprintf(ptr, left, " PROTO=TCP SRCPORT=%u DSTPORT=%u",
                    ntohs(tcp->source), ntohs(tcp->dest));
            } else if (ip->protocol == IPPROTO_UDP) {
                struct udphdr *udp =
                    (struct udphdr*)((unsigned int*)ip + ip->ihl);
                len = snprintf(ptr, left, " PROTO=UDP SRCPORT=%u DSTPORT=%u",
                    ntohs(udp->source), ntohs(udp->dest));
            }
            if (len < 0)
                goto out;
            left -= len;
            ptr += len;
        }
    }

    if (strlen(action) > 0) {
        len = snprintf(ptr, left, " act=%s", action);
        if (len < 0)
            goto out;
        left -= len;
        ptr += len;
    }

out:
    log[LOG_MSG_SIZE - left] = '\n';
    log[LOG_MSG_SIZE - left + 1] = 0;
    log_event(log);

    return SENTRY_OK;
}

/***********************************************************************
 * function:    ip_logger_task
 * description: the logger task. create a socket connected to NFLOG and
 *              and wait for msgs from NFLOG. each msg will be parsed
 *              and logged.
 * in param:    void *data (not used).
 * return:      n/a
 **********************************************************************/
static void* ip_logger_task(void *data)
{
    int ret, fd;
    char buf[LOG_MSG_SIZE];
    struct nflog_handle *handle = NULL;
    struct nflog_g_handle *group = NULL;
    fd_set rfds;

    memset(buf, 0, sizeof(buf));

    handle = nflog_open();
    if (!handle){
        sentry_error("Could not get netlink handle\n");
        ip_logger_thread_id = 0;
        return NULL;
    }

    if (nflog_bind_pf(handle, AF_INET) < 0) {
        sentry_error("nflog_bind_pf failed: %s\n", strerror(errno));
        goto out;
    }

    group = nflog_bind_group(handle, 0);
    if (!group) {
        sentry_error("nflog_bind_group failed: %s\n", strerror(errno));
        goto out;
    }

    if (nflog_set_mode(group, NFULNL_COPY_PACKET, 0xffff) < 0) {
        sentry_error("nflog_set_mode failed: %s\n", strerror(errno));
        goto unbind_out;
    }

    nflog_callback_register(group, &parse_msg, NULL);

    /* get fd */
    fd = nflog_fd(handle);

    while (true) {
        FD_ZERO(&rfds);

        /* watch for netlink event or on the pipe (i.e. exit) without timeout */
        FD_SET(fd, &rfds);
        FD_SET(ip_pipe_fds[0], &rfds);

        ret = select((MAX(fd,ip_pipe_fds[0]) + 1), &rfds, NULL, NULL, NULL);
        if (ret > 0) {
            if (FD_ISSET(ip_pipe_fds[0] , &rfds)) {
                sentry_debug("ip_logger_task exit ...\n");
                break;
            }

            ret = recv(fd, buf, LOG_MSG_SIZE, 0);
            if (ret > 0 )
                nflog_handle_packet(handle, buf, ret);
            else
                sentry_error("recv failed %s\n", strerror(errno));
        } else if (ret < 0)
            sentry_error("select failed: %s\n", strerror(ret));
    }

unbind_out:
    nflog_unbind_group(group);

out:
    nflog_close(handle);

    pthread_detach(pthread_self());

    ip_logger_thread_id = 0;

    return NULL;
}

/***********************************************************************
 * function:    add_del_default_cmds
 * description: add/del some iptables cmds
 * in param:    bool add
 * return:      SENTRY_OK/SENTRY_ERR
 **********************************************************************/
int add_del_default_cmds(bool add)
{
    int i, max;
    char cmd[STR_MAX_SIZE];

    if (iptables_ver >= IPTABLES_VER(1, 6, 1))
        max = ARRAYSIZE(default_iptables_cmds_size);
    else
        max = ARRAYSIZE(default_iptables_cmds_range);

    for (i = 0; i < max; i++) {
        if (iptables_ver >= IPTABLES_VER(1, 6, 1))
            snprintf(cmd, STR_MAX_SIZE, "iptables %s %s", add?"-A":"-D", default_iptables_cmds_size[i]);
        else
            snprintf(cmd, STR_MAX_SIZE, "iptables %s %s", add?"-A":"-D", default_iptables_cmds_range[i]);
        if (system(cmd) < 0) {
            sentry_debug("%s\n", cmd);
            sentry_error("system failed for %s\n", cmd);
        }
    }

    return SENTRY_OK;
}

/***********************************************************************
 * function:    ip_init
 * description: init the ip module
 * return:      SENTRY_OK/SENTRY_ERR
 **********************************************************************/
int ip_init(void)
{
    FILE *ver_pipe;
    char iptables_ver_str[STR_MAX_SIZE];
    int major = 0, minor = 0, patch = 0;

    ver_pipe = popen("iptables -V", "r");
    if (NULL == ver_pipe) {
        sentry_error("ver_pipe failed %s\n", strerror(errno));
        return SENTRY_ERR;
    }

    if (fgets(iptables_ver_str, STR_MAX_SIZE, ver_pipe)) {
        if (strlen(iptables_ver_str) > 0) {
            if (sscanf(iptables_ver_str, "iptables v%d.%d.%d", &major, &minor, &patch) == 3) {
                sentry_debug("iptables_ver major %d, minor %d, patch %d\n", major, minor, patch);
                iptables_ver = IPTABLES_VER(major, minor, patch);
            }
        }
    } else {
        sentry_error("failed getting iptables version\n");
        pclose(ver_pipe);
        return SENTRY_ERR;
    }

    pclose(ver_pipe);

    list_init(&ip_rules_list, ip_rule_search_cb, NULL, ip_rule_compare_cb);

    if (pipe(ip_pipe_fds) < 0){
        sentry_error("pipe failed %s\n", strerror(errno));
        return SENTRY_ERR;
    }

    if (pthread_create(&ip_logger_thread_id, NULL, &ip_logger_task,
            NULL) != 0) {
        sentry_error("cant create ip logger thread\n");
        ip_logger_thread_id = 0;
        return SENTRY_ERR;
    }

    constract_sentry_ipchains(true);

    return SENTRY_OK;
}

/***********************************************************************
 * function:    ip_deinit
 * description: deinit the can module
 * return:      SENTRY_OK/SENTRY_ERR
 **********************************************************************/
void ip_deinit(void)
{
    node_t *ptr = ip_rules_list.head;
    ip_rule *ip_rule_ptr;

    while(ptr) {
        ip_rule_ptr = (ip_rule*)ptr->data;
        if (ip_rule_ptr) {
            int in_idx = 0, out_idx = 0;

            if (ip_rules_get_idxs(ip_rule_ptr, &out_idx, &in_idx) == SENTRY_OK)
                constract_iptable_cmd(NULL, SENTRY_OP_DELETE, NULL, out_idx, in_idx);
            list_remove_node(&ip_rules_list, ptr);
            free(ip_rule_ptr);
        }
        ptr = ip_rules_list.head;
    }

    add_del_default_cmds(false);
    constract_sentry_ipchains(false);

    /* signal logger thread to exit */
    if (write(ip_pipe_fds[1], "STOP", 4) < 0)
        sentry_error("write to pipe failed: %s\n", strerror(errno));

    if (ip_logger_thread_id)
        pthread_join(ip_logger_thread_id, NULL);
}

/***********************************************************************
 * function:    action_search_by_name
 * description: search for an action in the list by name.
 * in param:    char *name - the action name.
 * return:      action_t*
 **********************************************************************/
static ip_rule* ip_rule_search_by_ids(unsigned short rulenum, unsigned int tuple_id)
{
    node_t *candidate = NULL;
    ip_rule ids = {
        .rulenum = rulenum,
        .tuple_id = tuple_id,
    };

    candidate = list_search_node(&ip_rules_list, &ids);
    if (!candidate)
        return NULL;

    return (ip_rule*)candidate->data;
}

/***********************************************************************
 * function:    ip_rule_create
 * description: add new can rule to ip_rules_list
 * in param:    action_t *new_action
 * SENTRY_OK/SENTRY_ERR
 **********************************************************************/
static int ip_rule_create(ip_rule_t *rule)
{
    ip_rule *new_rule = NULL;
    int in_idx = 0, out_idx = 0;

    if (!rule)
        return SENTRY_ERR;

    new_rule = ip_rule_search_by_ids(rule->rulenum, rule->tuple.id);
    if (new_rule) {
        sentry_error("can rule [%d/%d] already exist\n", rule->rulenum, rule->tuple.id);
        return SENTRY_ERR;
    }

    /* alocate new action_t struct */
    new_rule = malloc(sizeof(ip_rule));
    if (!new_rule) {
        sentry_error("cant allocate memory for new can rule\n");
        return SENTRY_ERR;
    }

    memset(new_rule, 0, sizeof(ip_rule));
    new_rule->tuple_id = rule->tuple.id;
    new_rule->rulenum = rule->rulenum;

    if (rule->tuple.srcaddr.s_addr == 0x100007F) {
        if (rule->tuple.dstaddr.s_addr == 0x100007F) {
            new_rule->direction = SENTRY_DIR_BOTH;
            sentry_debug("cretaed direction BOTH\n");
        } else {
            new_rule->direction = SENTRY_DIR_OUT;
            sentry_debug("cretaed direction OUT\n");
        }
    }
    else if (rule->tuple.dstaddr.s_addr == 0x100007F) {
        new_rule->direction = SENTRY_DIR_IN;
        sentry_debug("cretaed direction IN\n");
    } else {
        new_rule->direction = SENTRY_DIR_BOTH;
        sentry_debug("cretaed direction BOTH\n");
    }

    new_rule->action = action_search_by_name(rule->action_name);
    if (!new_rule->action) {
        sentry_error("failed to find action %s\n", rule->action_name);
        free(new_rule);
        return SENTRY_ERR;
    }

    /* add the new action to list */
    if (list_add_sorted(&ip_rules_list, new_rule) == NULL) {
        sentry_error("failed to add the new can rule to list\n");
        free(new_rule);
        return SENTRY_ERR;
    }

    if (ip_rules_get_idxs(new_rule, &out_idx, &in_idx) == SENTRY_OK)
        constract_iptable_cmd(rule, SENTRY_OP_CREATE, new_rule->action,
            out_idx, in_idx);

    sentry_debug("created ip rule [%d,%d]\n", rule->rulenum, rule->tuple.id);

    return SENTRY_OK;
}

/***********************************************************************
 * function:    ip_rule_delete
 * description: delete can rule from the list. search by ref ip_rule_t
 * in param:    action_t *
 * return:      SENTRY_OK/SENTRY_ERR
 **********************************************************************/
static int ip_rule_delete(ip_rule_t *rule)
{
    node_t *candidate = NULL;
    ip_rule *del_rule = NULL;
    int in_idx = 0, out_idx = 0;
    ip_rule ids = {
        .rulenum = rule->rulenum,
        .tuple_id = rule->tuple.id,
    };

    if (!rule)
        return SENTRY_ERR;

    candidate = list_search_node(&ip_rules_list, &ids);
    if (!candidate) {
        sentry_error("couldn't find can rule [%d,%d]\n", rule->rulenum, rule->tuple.id);
        return SENTRY_ERR;
    }

    del_rule = (ip_rule*)candidate->data;
    if (!del_rule) {
        sentry_error("failed to remove node\n");
        return SENTRY_ERR;
    }

    if (ip_rules_get_idxs(del_rule, &out_idx, &in_idx) == SENTRY_OK)
        constract_iptable_cmd(rule, SENTRY_OP_DELETE, NULL, out_idx, in_idx);

    list_remove_node(&ip_rules_list, candidate);
    free(del_rule);

    sentry_debug("deleted ip rule [%d,%d]\n", rule->rulenum, rule->tuple.id);

    return SENTRY_OK;
}

/***********************************************************************
 * function:    ip_rule_modify
 * description: modify ip rule on the list. search by ref ip_rule_t
 * in param:    ip_rule_t *rule
 * return:      SENTRY_OK/SENTRY_ERR
 **********************************************************************/
static int ip_rule_modify(ip_rule_t *rule)
{
    ip_rule *mod_rule = NULL;
    unsigned int direction = 0;
    int in_idx = 0, out_idx = 0;
    unsigned int diff_direction = 0, del_direction = 0, add_direction = 0;

    if (!rule)
        return SENTRY_ERR;

    /* get the rule struct from the maintained ip rules list */
    mod_rule = ip_rule_search_by_ids(rule->rulenum, rule->tuple.id);
    if (!mod_rule) {
        sentry_error("couldn't find can rule [%d,%d]\n", rule->rulenum, rule->tuple.id);
        return SENTRY_ERR;
    }

    /* get the modified rule direction */
    if (rule->tuple.srcaddr.s_addr == 0x100007F) {
        if (rule->tuple.dstaddr.s_addr == 0x100007F) {
            direction = SENTRY_DIR_BOTH;
            sentry_debug("modified direction BOTH\n");
        } else {
            direction = SENTRY_DIR_OUT;
            sentry_debug("modified direction OUT\n");
        }
    }
    else if (rule->tuple.dstaddr.s_addr == 0x100007F) {
        direction = SENTRY_DIR_IN;
        sentry_debug("modified direction IN\n");
    } else {
        direction = SENTRY_DIR_BOTH;
        sentry_debug("modified direction BOTH\n");
    }

    mod_rule->action = action_search_by_name(rule->action_name);
    if (!mod_rule->action) {
        sentry_error("failed to find action %s\n", rule->action_name);
        return SENTRY_ERR;
    }

    if (mod_rule->direction != direction) {
        /* direction changed .. lets see if we need to remove/add something
         * from/to iptables */
        diff_direction = (mod_rule->direction ^ direction);
        del_direction  = (mod_rule->direction & diff_direction);
        add_direction  = (diff_direction & direction);

        /* get the existing rule indexes in the iptables */
        if (ip_rules_get_idxs(mod_rule, &out_idx, &in_idx) != SENTRY_OK) {
            sentry_error("couldn't find can indexes for rule [%d,%d]\n",
                rule->rulenum, rule->tuple.id);
            return SENTRY_ERR;
        }

        /* handle del */
        if (del_direction) {
            /* old rule included a direction that is not included in the
             * new rule, it should be delete */
            if ((del_direction & SENTRY_DIR_IN) && (in_idx > 0)) {
                sentry_debug("deleting input rule at %d\n", in_idx);
                constract_iptable_cmd(rule, SENTRY_OP_DELETE, NULL, 0, in_idx);
            }
            if ((del_direction & SENTRY_DIR_OUT) && (out_idx > 0)) {
                sentry_debug("deleting output rule at %d\n", out_idx);
                constract_iptable_cmd(rule, SENTRY_OP_DELETE, NULL, out_idx, 0);
            }
        }

        /* before handling add we need to update the direction so we can
         * get the correct index of the new rule in the list */
        mod_rule->direction = direction;
        /* get the updated rule indexes in the iptables */
        if (ip_rules_get_idxs(mod_rule, &out_idx, &in_idx) != SENTRY_OK) {
            sentry_error("couldn't find can indexes for rule [%d,%d]\n",
                rule->rulenum, rule->tuple.id);
            return SENTRY_ERR;
        }
        /* handle add */
        if (add_direction) {
            /* new rule include a direction that was not included in the
             * old rule, it should be added */
            if ((add_direction & SENTRY_DIR_IN) && (in_idx > 0)) {
                sentry_debug("creating new input rule at %d\n", in_idx);
                constract_iptable_cmd(rule, SENTRY_OP_CREATE, mod_rule->action, 0, in_idx);
            }
            if ((add_direction & SENTRY_DIR_OUT) && (out_idx > 0)) {
                sentry_debug("creating new output rule at %d\n", out_idx);
                constract_iptable_cmd(rule, SENTRY_OP_CREATE, mod_rule->action, out_idx, 0);
            }
        }
    }

    mod_rule->direction = direction;
    if (ip_rules_get_idxs(mod_rule, &out_idx, &in_idx) != SENTRY_OK) {
        sentry_error("couldn't find can indexes for rule [%d,%d]\n",
            rule->rulenum, rule->tuple.id);
        return SENTRY_ERR;
    }

    /* if we already added a rule in a new direction we dont need to modify it */
    if (add_direction & SENTRY_DIR_IN) {
        sentry_debug("input direction already added\n");
        in_idx = 0;
    }
    if (add_direction & SENTRY_DIR_OUT) {
        sentry_debug("output direction already added\n");
        out_idx = 0;
    }

    constract_iptable_cmd(rule, SENTRY_OP_MODIFY, mod_rule->action, out_idx, in_idx);

    sentry_debug("modified ip rule [%d,%d]\n", rule->rulenum, rule->tuple.id);

    return SENTRY_OK;
}

/***********************************************************************
 * function:    action_handle_event
 * description: handle action event
 * in param:    action_t *
 * return:      SENTRY_OK/SENTRY_ERR
 **********************************************************************/
int ip_handle_event(int op, ip_rule_t *rule)
{
    switch (op) {
    case SENTRY_OP_CREATE:
        return ip_rule_create(rule);
    case SENTRY_OP_DELETE:
        return ip_rule_delete(rule);
    case SENTRY_OP_MODIFY:
        return ip_rule_modify(rule);
    default:
        return SENTRY_ERR;
    }
}

/***********************************************************************
 * function:    ip_enable
 * description: enable disable the log/log_drop iptables
 * in param:    bool enable
 * return:      SENTRY_OK/SENTRY_ERR
 **********************************************************************/
int ip_enable(bool enable)
{
    int i = 0;
    char cmd[STR_MAX_SIZE];

    for (i=(LOG_SEVERITY_NONE+1); i<LOG_SEVERITY_TOTAL; i++) {
        /* TODO: add "-m limit --limit 100/minute" */

        if (enable) {
            /* add a rule the log chain */
            if (iptables_ver >= IPTABLES_VER(1, 6, 1)) {
                snprintf(cmd, STR_MAX_SIZE,
                    "iptables -A %s -j NFLOG --nflog-size 64 --nflog-prefix \"level=%s act=log\"",
                    sentry_ip_log_chains[i], sentry_ip_severity_str[i]);
            } else {
                snprintf(cmd, STR_MAX_SIZE,
                    "iptables -A %s -j NFLOG --nflog-range 64 --nflog-prefix \"level=%s act=log\"",
                    sentry_ip_log_chains[i], sentry_ip_severity_str[i]);
            }
            if (system(cmd) < 0)
                sentry_error("system failed for %s\n", cmd);

            /* add a rule the log_drop chain */
            if (iptables_ver >= IPTABLES_VER(1, 6, 1)) {
                snprintf(cmd, STR_MAX_SIZE,
                    "iptables -A %s -j NFLOG --nflog-size 64 --nflog-prefix \"level=%s act=drop\"",
                    sentry_ip_log_drop_chains[i], sentry_ip_severity_str[i]);
            } else {
                snprintf(cmd, STR_MAX_SIZE,
                    "iptables -A %s -j NFLOG --nflog-range 64 --nflog-prefix \"level=%s act=drop\"",
                    sentry_ip_log_drop_chains[i], sentry_ip_severity_str[i]);
            }
            if (system(cmd) < 0)
                sentry_error("system failed for %s\n", cmd);

            snprintf(cmd, STR_MAX_SIZE,
                "iptables -A %s -j DROP", sentry_ip_log_drop_chains[i]);
            if (system(cmd) < 0)
                sentry_error("system failed for %s\n", cmd);
        } else {
            /* flush all rules from log chain */
            snprintf(cmd, STR_MAX_SIZE, "iptables -F %s",
                sentry_ip_log_chains[i]);
            if (system(cmd) < 0)
                sentry_error("system failed for %s\n", cmd);

            /* flush all rules from log_drop chain */
            snprintf(cmd, STR_MAX_SIZE, "iptables -F %s",
                sentry_ip_log_drop_chains[i]);
            if (system(cmd) < 0)
                sentry_error("system failed for %s\n", cmd);
        }
    }

    add_del_default_cmds(enable);

    return SENTRY_OK;
}
