#ifndef SENTRY_H
#define SENTRY_H

#include <stdio.h>

#define XPATH_MAX_LEN           512
#define USER_NAME_SIZE          128
#define PROG_NAME_SIZE          256
#define INTERFACE_SIZE          16

#define SENTRY_ERR (-1)
#define SENTRY_OK   0

#define SENTRY_DIR_IN           1<<0
#define SENTRY_DIR_OUT          1<<1
#define SENTRY_DIR_BOTH         (SENTRY_DIR_IN | SENTRY_DIR_OUT)

typedef enum {
    SENTRY_ENTRY_ACTION, /* action must be first */
    SENTRY_ENTRY_CAN,
    SENTRY_ENTRY_IP,
    SENTRY_ENTRY_FILE,
    SENTRY_ENTRY_ENG,
    SENTRY_ENTRY_TYPE_MAX   = SENTRY_ENTRY_ENG,
    SENTRY_ENTRY_TYPE_TOTAL = (SENTRY_ENTRY_TYPE_MAX + 1),
} sentry_entry_type;

#define STR_ACTION_XPATH    "/saferide:config/sr_actions"
#define STR_IP_XPATH        "/saferide:config/net/ip"
#define STR_CAN_XPATH       "/saferide:config/net/can"
#define STR_FILE_XPATH      "/saferide:config/system/file"
#define STR_ENG_XPATH       "/saferide:control/engine"

typedef enum {
    SENTRY_OP_CREATE,
    SENTRY_OP_DELETE,
    SENTRY_OP_MODIFY,
    SENTRY_OP_MAX     = SENTRY_OP_MODIFY,
    SENTRY_OP_TOTAL   =(SENTRY_OP_MAX + 1),
} sentry_op_e;

/* engine state */
typedef enum {
    ENGINE_STATE_START,
    ENGINE_STATE_STOP,
    ENGINE_STATE_RELOAD,
    ENGINE_STATE_MAX = ENGINE_STATE_RELOAD,
    ENGINE_STATE_TOTAL = (ENGINE_STATE_MAX + 1),
} engine_state_e;

#define sentry_debug(fmt, args...) \
    fprintf(stderr, "DEBUG: %s(): " fmt, __func__, ##args)
#define sentry_error(fmt, args...) \
    fprintf(stderr, "ERROR: %s(): " fmt, __func__, ##args)
#define sentry_warn(fmt, args...) \
    fprintf(stderr, "WARN: %s(): " fmt, __func__, ##args)

typedef void (*sentry_callback)(int, int, void*);

int     sentry_init(sentry_callback sentry_cb);
int     sentry_stop(void);

#endif /* SENTRY_H */
