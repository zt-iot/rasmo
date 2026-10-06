#ifndef _ACCESS_CONTROL_H
#define _ACCESS_CONTROL_H

#include <netinet/in.h>

// SHA256 in hex plus '\0'
#define FINGERPRINT_LEN ( 32 * 2 + 1 )

// including ipv6 addresses
#define IP_ADDR_LEN (INET6_ADDRSTRLEN + 1)

/* key: IP address */
struct access_attempt {
	int num_failed;
	int maxretry;
	char ip_addr[IP_ADDR_LEN];
	char fingerprint[FINGERPRINT_LEN];
};

#define OP_BLOCK	0
#define OP_UNBLOCK	1

struct ip_batch {
	int op; /* OP_BLOCK or OP_UNBLOCK */
	char ip_addr[IP_ADDR_LEN];
};

#endif
