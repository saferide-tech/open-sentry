#include <unistd.h>
#include "sentry.h"
#include "internal_api.h"

/***********************************************************************
 * function:    test main
 * description: 
 * in param:    
 * return:      
 **********************************************************************/
char *type_str[SENTRY_ENTRY_TYPE_TOTAL] = {
    "action",
    "can",
    "ip",
    "file",
    "eng",
};

char *op_str[SENTRY_OP_TOTAL] = {
    "create",
    "delete",
    "modify",
};

void test_cb(int type, int op, void *entry)
{
    sentry_debug("%s %s:\n", op_str[op], type_str[type]);
    switch (type) {
    case SENTRY_ENTRY_ACTION:
        action_display((action_t*)entry);
        break;
    case SENTRY_ENTRY_IP:
        ip_rule_display((ip_rule_t*)entry);
        break;
    case SENTRY_ENTRY_CAN:
        can_rule_display((can_rule_t*)entry);
        break;
    case SENTRY_ENTRY_FILE:
        file_rule_display((file_rule_t*)entry);
        break;
    case SENTRY_ENTRY_ENG:
        sentry_debug("engine state %s\n", (char*)entry);
        break;
    default:
        break;
    }
}

#include <signal.h>

bool exit_application = false;

static void sigint_handler(int signum)
{
    exit_application = true;
}

int main(int argc, char **argv)
{
    sentry_init(test_cb);

    /* loop until ctrl-c is pressed / SIGINT is received */
    signal(SIGINT, sigint_handler);
    signal(SIGPIPE, SIG_IGN);
    while (!exit_application)
        sleep(1);

    sentry_stop();

    return 0;
}
