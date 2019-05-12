#ifndef ACTION_H
#define ACTION_H

#include "sentry.h"

#define ACTION_STR_SIZE     32

#define ACTION_NAME_XPATH_PREFIX "/saferide:config/sr_actions/list_actions[name='%s"

typedef enum {
    ACTION_NONE,
    ACTION_DROP,
    ACTION_ALLOW,
    ACTION_MAX = ACTION_ALLOW,
    ACTION_TOTAL = (ACTION_MAX + 1),
} action_e;

typedef enum {
    LOG_NONE,
    LOG_TO_SYSLOG, /* TODO: not supported yet */
    LOG_TO_FILE,
    LOG_MAX = LOG_TO_FILE,
    LOG_TOTAL = (LOG_MAX + 1),
} log_facility_e;

typedef enum {
    LOG_SEVERITY_NONE,
    LOG_SEVERITY_CRT,
    LOG_SEVERITY_ERR,
    LOG_SEVERITY_WARN,
    LOG_SEVERITY_INFO,
    LOG_SEVERITY_DEBUG,
    LOG_SEVERITY_MAX = LOG_SEVERITY_DEBUG,
    LOG_SEVERITY_TOTAL = (LOG_SEVERITY_MAX + 1),
} log_severity_e;

typedef struct {
    char             action_name[ACTION_STR_SIZE];
    action_e         action;
    log_facility_e   log_facility;
    log_severity_e   log_severity;
    int              black_list;
    int              terminate;
} action_t;

void action_display(action_t *action);

#endif /*ACTION_H */

