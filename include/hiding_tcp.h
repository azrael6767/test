#ifndef UB_NETGUARD_H
#define UB_NETGUARD_H

int ub_netguard_start(void);
void ub_netguard_stop(void);
notrace long ub_netlink_mask(int protocol, unsigned char *buf, long len);
notrace long filter_sock_diag_messages(unsigned char *buf, long len);
notrace long filter_conntrack_messages(unsigned char *buf, long len);

#endif
