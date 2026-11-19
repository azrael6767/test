#ifndef UB_ARMOR_H
#define UB_ARMOR_H

#include <linux/sched.h>

notrace int  ub_armor_bootstrap_kprobe_hook(void);
notrace void ub_armor_protect_symbol(const char *symname);
notrace int  ub_armor_start(void);
notrace void ub_armor_stop(void);

notrace void ub_armor_register_phys_range(const void *va, size_t size);
notrace void ub_armor_register_hidden_task(struct task_struct *task);

#endif