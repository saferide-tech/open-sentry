#ifndef CAN_MODULE_H
#define CAN_MODULE_H

#include "can_rule.h"

int  can_handle_event(int op, can_rule_t *rule);
int  can_init(void);
void can_deinit(void);
int can_enable(bool enable);

#endif /* CAN_MODULE_H */
