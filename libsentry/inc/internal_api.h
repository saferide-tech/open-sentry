#ifndef INTERNAL_API_H
#define INTERNAL_API_H

#include "list.h"
#include "action.h"
#include "can_rule.h"
#include "file_rule.h"
#include "ip_rule.h"
#include "sentry.h"

int action_get_name(action_t *action, char *xpath);
int action_init_list(void);
void action_clear_list(void);

int can_rule_get_id(can_rule_t *can_rule, char *xpath);
int can_rule_init_list(void);
void can_rule_clear_list(void);

int file_rule_get_id(file_rule_t *file_rule, char *xpath);
int file_rule_init_list(void);
void file_rule_clear_list(void);

int ip_rule_get_id(ip_rule_t *ip_rule, char *xpath);
int ip_rule_init_list(void);
void ip_rule_clear_list(void);

#endif /* INTERNAL_API_H */
