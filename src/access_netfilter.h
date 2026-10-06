#ifndef _ACCESS_NETFILTER_H_
#define _ACCESS_NETFILTER_H_

#include "access_control.h"

/* create blocklist netfilter structures in kernel */
int netfilter_init(void);
int netfilter_op(struct ip_batch*, int);

#endif
