#ifndef ACTION_MODULE_H
#define ACTION_MODULE_H

#include "action.h"

void action_init(void);
void action_deinit(void);
action_t *action_search_by_name(char *name);
int action_handle_event(int op, action_t *action);

#endif /* ACTION_MODULE_H */
