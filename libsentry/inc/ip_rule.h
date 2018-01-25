#ifndef IP_RULE_H
#define IP_RULE_H

#include <netinet/in.h>
#include "sentry.h"
#include "action.h"

#define IP_RULE_ACT_XPATH_FORMAT "/saferide:config/net/ip/rule[num='%d']/action"
#define IP_TUPLES_XPATH_FORMAT   "/saferide:config/net/ip/rule[num='%d']/tuple"
#define IP_TUPLEID_XPATH_FORMAT  "/saferide:config/net/ip/rule[num='%d']/tuple[id='%d']"

typedef struct {
    unsigned int    id;
    struct in_addr  srcaddr;
    struct in_addr  srcnetmask;
    struct in_addr  dstaddr;
    struct in_addr  dstnetmask;
    unsigned short  dstport;
    unsigned short  srcport;
    unsigned char   proto;
    char            user[USER_NAME_SIZE];
    char            program[PROG_NAME_SIZE];
    unsigned int    max_rate;
} ip_tuple_t;

typedef struct {
    unsigned short  rulenum;
    ip_tuple_t      tuple;
    char            action_name[ACTION_STR_SIZE];
} ip_rule_t;

void ip_rule_display(ip_rule_t *ip_rule);

#endif /* IP_RULE_H */
