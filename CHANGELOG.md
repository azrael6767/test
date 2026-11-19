# UMBRA changelog

## 1.0.0

- Forked the public Singularity codebase under a new identity (`umbra.ko`).
- Renamed every project-defined symbol to the `ub_*` namespace; rebuilt the
  public header API and source layout.
- Replaced the ICMP-triggered `/dev/tcp` reverse shell with a beacon keeper
  that fetches an operator-selected implant (Sliver / Metasploit / custom).
- Added ring-0 liveness supervision: dead or killed beacons are re-fetched and
  relaunched automatically.
- Added polymorphic naming: artifact, ghost process title and pidfile are
  rotated on every generation.
- Added a hidden userspace guardian driven by a kernel heartbeat; unloading
  the module causes it to be reinserted and a new beacon generation to start.
- Converted beacon settings to module parameters; `setup.sh` now prompts for
  URL/profile/args and stages the module image for the guardian.
- Fixed the kernel-side stack frame in the deployment path by moving command
  buffers to `kmalloc`.
- Refreshed README, ASCII branding, trigger script and hidden-path patterns.
