#ifndef UB_AUDIT_GUARD_H
#define UB_AUDIT_GUARD_H

notrace int ub_auditguard_start(void);
notrace void ub_auditguard_stop(void);
notrace int ub_audit_blocked_count(void);
notrace int ub_audit_total_count(void);
notrace void ub_veil_socket_inode(unsigned long ino);

#endif
