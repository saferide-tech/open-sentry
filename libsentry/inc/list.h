#ifndef LIST_H
#define LIST_H

#include <stdbool.h>

/* return value when comaring 2 list elements */
typedef enum {
    NODE_CMP_SMALLER,
    NODE_CMP_EQUAL,
    NODE_CMP_BIGGER,
} node_cmp_e;

/* callback functions prototypes used by the list */
typedef bool (*list_search_cb) (void *candidate, void *data);
typedef void (*list_print_cb)  (void *data);
typedef int  (*list_compare_cb)(void *a, void *b);
typedef void  (*list_exec_cb)(void *data, void *param);

/* list element */
typedef struct node_t {
    void           *data;
    struct node_t  *next;
} node_t;

/* the list */
typedef struct {
    node_t*         head;
    list_search_cb  search;
    list_print_cb   print;
    list_compare_cb compare;
    int             count;
} list_t;

/* list functions */
list_t*  list_init(list_t *list, list_search_cb scb, list_print_cb pcb, list_compare_cb ccb);
node_t*  list_append(list_t *list, void *data);
node_t*  list_add_sorted(list_t *list, void *data);
void*    list_remove_node(list_t *list, node_t *nd);
node_t*  list_search_node(list_t *list, void *data);
void     list_print(list_t *list);
void     list_exec_for_each(list_t *list, list_exec_cb cb, void *param);

#endif /* LIST_H */

