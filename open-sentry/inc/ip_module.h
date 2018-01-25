#ifndef IP_MODULE_H
#define IP_MODULE_H

#include "ip_rule.h"

int ip_handle_event(int op, ip_rule_t *rule);
int ip_init(void);
void ip_deinit(void);
int ip_enable(bool enable);

#endif /* IP_MODULE_H */
