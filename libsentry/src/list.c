#include <stdlib.h>
#include "list.h"

/***********************************************************************
 * function:    list_init
 * description: allocate new node and set its data.
 * in param:    list_t *list - the list to init
 *              os_search_cb scb - list search callback
 *              os_print_cb pcb - list print callback
 * return:      list_t* - the new allocated list. NULL on error.
 **********************************************************************/
list_t *list_init(list_t *list,
                  list_search_cb scb,
                  list_print_cb pcb,
                  list_compare_cb ccb)
{
    if (!list)
        return NULL;

    list->head = NULL;
    list->search = scb;
    list->print = pcb;
    list->compare = ccb;
    list->count = 0;

    return list;
}

/***********************************************************************
 * function:    node_create
 * description: allocate new node and set its data.
 * in param:    void *data - the data this node should contain.
 * return:      node_t* - the new allocated node. NULL on error.
 **********************************************************************/
static node_t *node_create(void *data)
{
    node_t *new_node = (node_t*)malloc(sizeof(node_t));
    if(new_node == NULL)
        return NULL;

    new_node->data = data;
    new_node->next = NULL;

    return new_node;
}

/***********************************************************************
 * function:    list_append
 * description: add a node to the end of the list.
 * in param:    list_t *list - the list to add to.
 *              void *data - the data this new node should contain.
 * return:      node_t* - the new node created. NULL on error.
 **********************************************************************/
node_t *list_append(list_t *list, void *data)
{
    node_t *tmp;

    if (!list || !data)
        return NULL;

    if (list->head == NULL) {
        list->head = node_create(data);
        list->count++;
        return list->head;
    }

    tmp = list->head;
    while(tmp->next != NULL)
        tmp = tmp->next;

    tmp->next = node_create(data);
    list->count++;

    return tmp->next;
}

/***********************************************************************
 * function:    list_add_sorted
 * description: add a node to the list in sorted way based on
 *              list_compare_cb function. head is the smallest.
 * in param:    list_t *list - the list to add to.
 *              void *data - the data this new node should contain.
 * return:      node_t* - the new node created. NULL on error.
 **********************************************************************/
node_t *list_add_sorted(list_t *list, void *data)
{
    node_t *smaller, *bigger, *new;

    if (!list || !list->compare || !data)
        return NULL;

    new = node_create(data);
    if (!new)
        return NULL;

    if (list->head == NULL) {
        list->head = new;
        list->count++;
        return list->head;
    }

    /* check if the list head is bigger */
    if (list->compare(list->head->data, data) == NODE_CMP_BIGGER) {
        /* set the new node a the list head */
        new->next = list->head;
        list->head = new;
        return new;
    }

    smaller = list->head;
    bigger = smaller->next;

    while (true) {
        if (!bigger ||
                (list->compare(bigger->data, data) == NODE_CMP_BIGGER)) {
            new->next = bigger;
            smaller->next = new;
            break;
        }
        smaller = bigger;
        bigger = bigger->next;
    }

    list->count++;

    return new;
}

/***********************************************************************
 * function:    list_remove_node
 * description: remove a node from the list.
 * in param:    list_t *list - the list to remove from.
 *              node_t *nd - the node to remove.
 * return:      void* - the data which was contained in the removed 
 *                      node. NULL if not found.
 **********************************************************************/
void *list_remove_node(list_t *list, node_t *nd)
{
    node_t *tmp = NULL;
    node_t *ptr = NULL;
    void* data = NULL;

    if (!list->head) {
        goto remove_exit;
    }

    if(list->head == nd) {
        ptr = list->head;
        list->head = list->head->next;
        goto remove_exit;
    }

    tmp = list->head;
    while (tmp->next) {
        if (tmp->next == nd) {
            ptr = tmp->next;
            tmp->next = tmp->next->next;
            break;
        }
        tmp = tmp->next;
    }

remove_exit:
    if (ptr) {
        list->count--;
        data = ptr->data;
        free(ptr);
    }

    return data;
}

/***********************************************************************
 * function:    list_search_node
 * description: search in the list for a node containing data.
 *              the function uses the search callback to deciede if the
 *              node contain the data or not.
 * in param:    list_t *list - the list to search in.
 *              void *data - the data we searching for.
 * return:      node_t* - NULL if not found.
 **********************************************************************/
node_t *list_search_node(list_t *list, void *data)
{
    node_t *ptr = NULL;

    if (!list || !list->search)
        return NULL;

    ptr = list->head;

    while(ptr) { 
        if (list->search(ptr->data, data))
            return ptr;
        ptr = ptr->next;
    }

    return NULL;
}

/***********************************************************************
 * function:    list_print
 * description: go over all list elements and invoke the list print
 *              callback per node.
 * in param:    list_t *list - the list to print.
 * return:      void.
 **********************************************************************/
void list_print(list_t *list)
{
    node_t *ptr = NULL;

    if (!list || !list->print)
        return;

    ptr = list->head;

    while(ptr) {
        list->print(ptr->data);
        ptr = ptr->next;
    }
}


