#include <unistd.h>
#include <stdbool.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include <string.h>
#include "action_module.h"
#include "can_module.h"
#include "ip_module.h"
#include "file_rule.h"
#include "sentry.h"
#include "open_sentry.h"

static int current_engine_state = ENGINE_STATE_STOP;

static char *engine_state_str[ENGINE_STATE_TOTAL] = {
    "start",
    "stop",
    "reload",
};

static int engine_state_str_to_enum(char *state)
{
    int i;

    for (i = 0; i < ENGINE_STATE_TOTAL; i++)
        if(strncmp(state, engine_state_str[i], strlen(state)) == 0)
            return i;
    return SENTRY_ERR;
}

/***********************************************************************
 * function:    
 * description: 
 * in param:    
 * return:      
 **********************************************************************/
void open_sentry_cb(int type, int op, void *entry)
{
    switch (type) {
    case SENTRY_ENTRY_ACTION:
        action_handle_event(op, (action_t*)entry);
        break;
    case SENTRY_ENTRY_IP:
        ip_handle_event(op, (ip_rule_t*)entry);
        break;
    case SENTRY_ENTRY_CAN:
        can_handle_event(op, (can_rule_t*)entry);
        break;
    case SENTRY_ENTRY_FILE:
        //not supported yet;
        break;
    case SENTRY_ENTRY_ENG:
        {
            int engine_state = engine_state_str_to_enum((char*)entry);

            sentry_debug("engine state %s\n", (char*)entry);
            if (engine_state != current_engine_state) {
                if (engine_state == ENGINE_STATE_STOP) {
                    can_enable(false);
                    ip_enable(false);
                }
                current_engine_state = engine_state;
                if (engine_state == ENGINE_STATE_START) {
                    can_enable(true);
                    ip_enable(true);
                }
            }
        }
        break;
    default:
        break;
    }
}

static FILE* log_file = NULL;
static pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;
long file_len = 0;
char *log_files[MAX_LOG_FILE_NUM];

/***********************************************************************
 * function:    
 * description: 
 * in param:    
 * return:      
 **********************************************************************/
static void rotat_log_files(void)
{
    int i;

    if (log_file)
        fclose(log_file);

    if (MAX_LOG_FILE_NUM > 1) {
        /* move log.x to log.x+1 */
        for (i = (MAX_LOG_FILE_NUM-1); i >= 0; i--) {
            if (!access(log_files[i], F_OK)) {
                if (rename(log_files[i], log_files[i+1]) < 0)
                    sentry_error("failed to rename %s, to %s\n",
                        log_files[i], log_files[i+1]);
            }
        }

        /* delete the oldest file */
        if (!access(log_files[MAX_LOG_FILE_NUM-1], F_OK)) {
            if (unlink(log_files[MAX_LOG_FILE_NUM-1]) < 0 )
                sentry_error("failed to delete %s\n",
                    log_files[MAX_LOG_FILE_NUM-1]);
        }
    }

    /* rewind/create the new log file */
    log_file = fopen(log_files[0], "w+");
    if (!log_file)
        sentry_error("failed to open %s: %s\n", log_files[0], strerror(errno));

    file_len = 0;
}

/***********************************************************************
 * function:    
 * description: 
 * in param:    
 * return:      
 **********************************************************************/
void log_event(char* event)
{
    int len;

    if (!log_file)
        return;

    pthread_mutex_lock(&log_lock);

    len = strlen(event);
    if ((file_len + len) > MAX_LOG_FILE_SIZE)
        rotat_log_files();

    if (fwrite(event, 1, len, log_file) < len)
        sentry_warn("fwrite return with less then %d\n", len);

    file_len += len;

    fflush(log_file);

    pthread_mutex_unlock(&log_lock);
}

/***********************************************************************
 * function:    
 * description: 
 * in param:    
 * return:      
 **********************************************************************/
 int init_logger(void)
 {
    int i;

    /* init the logging files */
    for (i = 0; i < MAX_LOG_FILE_NUM; i++) {
        log_files[i] = malloc(STR_MAX_SIZE);
        if (!log_files[i]) {
            sentry_error("failed to allocate log_file[%d]\n", i);
            return SENTRY_ERR;
        }

        if (i == 0)
            snprintf(log_files[i], STR_MAX_SIZE, "%s/%s", LOG_FILES_DIR, LOG_FILE);
        else
            snprintf(log_files[i], STR_MAX_SIZE, "%s/%s.%d", LOG_FILES_DIR, LOG_FILE, i);
    }

    log_file = fopen(log_files[0], "a+");
    if (!log_file) {
        sentry_error("fopen failed: %s %s\n", log_files[0], strerror(errno));
        return SENTRY_ERR;
    } else {
        file_len = ftell(log_file);
    }

    return SENTRY_OK;
}

bool exit_application = false;

static void sigint_handler(int signum)
{
    exit_application = true;
}

/***********************************************************************
 * function:    
 * description: 
 * in param:    
 * return:      
 **********************************************************************/
int main(int argc, char **argv)
{
    if (init_logger() != SENTRY_OK) {
        sentry_error("init_logger failed ... exiting\n");
        goto exit_log;
    }

    action_init();

    if (can_init() != SENTRY_OK) {
        sentry_error("can_init failed ... exiting\n");
        goto exit_can;
    }

    if (ip_init() != SENTRY_OK) {
        sentry_error("ip_init failed ... exiting\n");
        goto exit_ip;
    }

    if (sentry_init(open_sentry_cb) != SENTRY_OK) {
        sentry_error("sentry_init failed ... exiting\n");
        goto exit_sentry;
    }

    /* loop until ctrl-c is pressed / SIGINT is received */
    signal(SIGINT, sigint_handler);
    signal(SIGPIPE, SIG_IGN);

    while (!exit_application)
        sleep(1);

exit_sentry:
    sentry_stop();

exit_ip:
    ip_deinit();

exit_can:
    can_deinit();

    action_deinit();

exit_log:
    if (log_file)
        fclose(log_file);

    return 0;
}

