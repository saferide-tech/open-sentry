#ifndef CAN_RULE_H
#define CAN_RULE_H

#include "sentry.h"
#include "action.h"

#define CAN_RULE_ACT_XPATH_FORMAT "/saferide:config/net/can/rule[num='%d']/action"
#define CAN_TUPLES_XPATH_FORMAT   "/saferide:config/net/can/rule[num='%d']/tuple"
#define CAN_TUPLEID_XPATH_FORMAT  "/saferide:config/net/can/rule[num='%d']/tuple[id='%d']"

typedef struct {
    unsigned int    id;
    unsigned int    msg_id;
    unsigned char   direction;
    char            interface[INTERFACE_SIZE];
    char            user[USER_NAME_SIZE];
    char            program[PROG_NAME_SIZE];
    unsigned int    max_rate;
} can_tuple_t;

typedef struct {
    unsigned short  rulenum;
    can_tuple_t     tuple;
    char            action_name[ACTION_STR_SIZE];
} can_rule_t;

void can_rule_display(can_rule_t *can_rule);

#endif /* CAN_RULE_H */
