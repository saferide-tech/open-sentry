#ifndef FILE_RULE_H
#define FILE_RULE_H

#include "sentry.h"
#include "action.h"

#define FILE_NAME_SIZE          4096

#define FILE_RULE_ACT_XPATH_FORMAT "/saferide:config/system/file/rule[num='%d']/action"
#define FILE_TUPLES_XPATH_FORMAT   "/saferide:config/system/file/rule[num='%d']/tuple"
#define FILE_TUPLEID_XPATH_FORMAT  "/saferide:config/system/file/rule[num='%d']/tuple[id='%d']"

#define FILE_PERM_R (1 << 2)
#define FILE_PERM_W (1 << 1)
#define FILE_PERM_X (1 << 0)

typedef struct {
    unsigned int    id;
    char            filename[FILE_NAME_SIZE];
    char            permission[4];
    char            user[USER_NAME_SIZE];
    char            program[PROG_NAME_SIZE];
    unsigned int    max_rate;
} file_tuple_t;

typedef struct {
    unsigned short  rulenum;
    file_tuple_t    tuple;
    char            action_name[ACTION_STR_SIZE];
} file_rule_t;

void file_rule_display(file_rule_t *file_rule);

#endif /* FILE_RULE_H */
