#include <linux/module.h>
#include "hook_engine.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
#endif

#ifdef KPROBE_LOOKUP
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
kallsyms_lookup_name_t kallsyms_lookup_name_fn = NULL;
#endif

notrace unsigned long *ub_resolve_symbol(const char *symname)
{
    if (kallsyms_lookup_name_fn == NULL) {
#ifdef KPROBE_LOOKUP
        register_kprobe(&kp);
        kallsyms_lookup_name_fn = (kallsyms_lookup_name_t) kp.addr;
        unregister_kprobe(&kp);
#else
        kallsyms_lookup_name_fn = &kallsyms_lookup_name;
#endif
    }
    return (unsigned long *)kallsyms_lookup_name_fn(symname);
}

notrace int ub_fh_resolve_hook_address(struct ftrace_hook *hook)
{
    hook->address = (unsigned long)ub_resolve_symbol(hook->name);

    if (!hook->address) {
        pr_debug("hook_engine: unresolved symbol: %s\n", hook->name);
        return -ENOENT;
    }
#if USE_FENTRY_OFFSET
    *((unsigned long *)hook->original) = hook->address + MCOUNT_INSN_SIZE;
#else
    *((unsigned long *)hook->original) = hook->address;
#endif
    return 0;
}

/*
 * Kernel 6.x+ passes ftrace_regs to SAVE_REGS callbacks; older trees
 * hand us a pt_regs-compatible layout. Keep both variants instead of
 * relying on a cast that newer kernels may no longer honour.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
void notrace ub_fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
                             struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

#if USE_FENTRY_OFFSET
    ftrace_regs_set_instruction_pointer(fregs, (unsigned long)hook->function);
#else
    if (!within_module(parent_ip, THIS_MODULE))
        ftrace_regs_set_instruction_pointer(fregs, (unsigned long)hook->function);
#endif
}
#else
void notrace ub_fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
                             struct ftrace_ops *ops, struct pt_regs *regs)
{
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);
#if USE_FENTRY_OFFSET
    regs->ip = (unsigned long)hook->function;
#else
    if (!within_module(parent_ip, THIS_MODULE))
        regs->ip = (unsigned long)hook->function;
#endif
}
#endif

notrace int ub_fh_install_hook(struct ftrace_hook *hook)
{
    int err = ub_fh_resolve_hook_address(hook);
    if (err) return err;

    hook->ops.func  = (ftrace_func_t)ub_fh_ftrace_thunk;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS |
                      FTRACE_OPS_FL_RECURSION |
                      FTRACE_OPS_FL_IPMODIFY;

    err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
    if (err) {
        pr_debug("hook_engine: ftrace_set_filter_ip() failed: %d\n", err);
        return err;
    }
    err = register_ftrace_function(&hook->ops);
    if (err) {
        pr_debug("hook_engine: register_ftrace_function() failed for %s: %d\n",
                 hook->name, err);
        ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
        hook->address = 0;
        return err;
    }
    hook->active = true;
    return 0;
}

notrace void ub_fh_remove_hook(struct ftrace_hook *hook)
{
    int err;

    if (!hook || !hook->active)
        return;

    hook->active = false;
    err = unregister_ftrace_function(&hook->ops);
    if (err)
        pr_debug("hook_engine: unregister_ftrace_function() failed: %d\n", err);

    err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
    if (err)
        pr_debug("hook_engine: ftrace_set_filter_ip() failed: %d\n", err);
}

/*
 * Best-effort installation: kernels in the 6.x/7.x range rename or drop
 * internal symbols between minor releases. Losing one hook must not stop
 * the rest of the subsystem from loading.
 */
notrace int ub_fh_install_hooks(struct ftrace_hook *hooks, size_t count)
{
    size_t i, installed = 0;

    for (i = 0; i < count; i++) {
        if (ub_fh_install_hook(&hooks[i]) == 0)
            installed++;
    }

    if (!installed && count)
        return -ENOENT;

    pr_info("hook_engine: %zu/%zu hooks installed\n", installed, count);
    return 0;
}

notrace void ub_fh_remove_hooks(struct ftrace_hook *hooks, size_t count)
{
    size_t i;
    for (i = 0; i < count; i++)
        ub_fh_remove_hook(&hooks[i]);
}
