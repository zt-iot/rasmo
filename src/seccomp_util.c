#define _GNU_SOURCE
#include <sched.h>

#include <stdio.h>
#include <ctype.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <sys/mman.h>

// saddr
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <netinet/tcp.h>

// futex
#include <linux/futex.h>

#include "rasmo_util.h"
#include "seccomp_util.h"

struct dictionary file_flags_dict[] = {
	/* openat() flags */
	{ O_RDONLY, "O_RDONLY" },
	{ O_WRONLY, "O_WRONLY" },
	{ O_RDWR, "O_RDWR" },
	{ O_CLOEXEC, "O_CLOEXEC" },
	{ O_PATH, "O_PATH" },
	{ O_SYNC, "O_SYNC" },
	{ O_ASYNC, "O_ASYNC" },
	{ O_APPEND, "O_APPEND" },
	{ O_CREAT, "O_CREAT" },
	{ O_DIRECTORY, "O_DIRECTORY" },
	{ O_NONBLOCK, "O_NONBLOCK" },
	{ O_NOFOLLOW, "O_NOFOLLOW" },
	{ O_NOCTTY, "O_NOCTTY" },
	{ O_EXCL, "O_EXCL"},
	{ 0 }
};

struct dictionary clone_flags_dict[] = {
	{ CLONE_VM, "CLONE_VM" },
	{ CLONE_FS, "CLONE_FS" },
	{ CLONE_FILES, "CLONE_FILES" },
	{ CLONE_SIGHAND, "CLONE_SIGHAND" },
	{ CLONE_THREAD, "CLONE_THREAD" },
	{ CLONE_SYSVSEM, "CLONE_SYSVSEM" },
	{ CLONE_SETTLS, "CLONE_SETTLS" },
	{ CLONE_PARENT_SETTID, "CLONE_PARENT_SETTID" },
	{ CLONE_CHILD_CLEARTID, "CLONE_CHILD_CLEARTID" },
	{ CLONE_CHILD_SETTID, "CLONE_CHILD_SETTID" },
	{ SIGCHLD, "SIGCHLD" },
	{ 0 }
};

struct dictionary mode_dict[] = {
	{ F_OK, "F_OK" },
	{ R_OK, "R_OK" },
	{ W_OK, "W_OK" },
	{ X_OK, "X_OK" },
	{ 0 }
};

struct dictionary prot_dict[] = {
	{ PROT_EXEC, "PROT_EXEC" },
	{ PROT_READ, "PROT_READ" },
	{ PROT_WRITE, "PROT_WRITE" },
	{ PROT_NONE, "PROT_NONE" },
	{ 0 }
};

struct dictionary mmap_flags_dict[] = {
	{ MAP_SHARED, "MAP_SHARED"},
	{ MAP_ANONYMOUS, "MAP_ANONYMOUS"},
	{ MAP_PRIVATE, "MAP_PRIVATE"},
	{ MAP_FIXED, "MAP_FIXED"},
	{ MAP_FIXED_NOREPLACE, "MAP_FIXED_NOREPLACE"},
	{ MAP_DENYWRITE, "MAP_DENYWRITE"},
	{ MAP_NONBLOCK, "MAP_NONBLOCK"},
	{ MAP_NORESERVE, "MAP_NORESERVE"},
	{ MAP_STACK, "MAP_STACK"},
	{ MAP_SYNC, "MAP_SYNC"},
	{ MAP_DROPPABLE, "MAP_DROPPABLE"},
	{ 0 }
};

struct dictionary sock_flags_dict[] = {
	/* socket-related flags */
	{ SOCK_STREAM, "SOCK_STREAM" },
	{ SOCK_NONBLOCK, "SOCK_NONBLOCK" },
	{ SOCK_CLOEXEC, "SOCK_CLOEXEC" },
	{ SOCK_DGRAM, "SOCK_DGRAM" },
	{ SOCK_PACKET, "SOCK_PACKET" },
	{ SOCK_SEQPACKET, "SOCK_SEQPACKET" },
	{ SOCK_RAW, "SOCK_RAW" },
	{ SOCK_RDM, "SOCK_RDM" },
	{ 0 }
};

struct dictionary domain_flags_dict[] = {
	/* domain flags */
	{ AF_UNIX, "AF_UNIX" },
	{ AF_INET, "AF_INET" },
	{ AF_INET6, "AF_INET6" },
	{ AF_NETLINK, "AF_NETLINK" },
	{ AF_PACKET, "AF_PACKET" },
	{ 0 }
};

struct dictionary msg_flags_dict[] = {
	/* msg flags */
	{ 0, "0" },
	{ MSG_WAITALL, "MSG_WAITALL" },
	{ MSG_NOSIGNAL, "MSG_NOSIGNAL" },
	{ MSG_CMSG_CLOEXEC, "MSG_CMSG_CLOEXEC" },
	{ MSG_DONTWAIT, "MSG_DONTWAIT" },
	{ 0 }
};

struct dictionary sop_flags_dict[] = {
	{ SOL_SOCKET, "SOL_SOCKET" },
	{ SOL_IP, "SOL_IP" },
	{ SOL_TCP, "SOL_TCP" },
	{ SOL_IPV6, "SOL_IPV6" },
	{ SO_REUSEADDR, "SO_REUSEADDR" },
	{ SO_REUSEPORT, "SO_REUSEPORT" },
	{ SO_SNDBUF, "SO_SNDBUF" },
	{ SO_BROADCAST, "SO_BROADCAST" },
	{ SO_ATTACH_FILTER, "SO_ATTACH_FILTER" },
	{ SO_PASSCRED, "SO_PASSCRED" },
	{ SO_PRIORITY, "SO_PRIORITY" },
	{ TCP_NODELAY, "TCP_NODELAY" },
	{ TCP_FASTOPEN, "TCP_FASTOPEN" },
	{ IP_TTL, "IP_TTL" },
	{ IP_TOS, "IP_TOS" },
	{ IPV6_TCLASS, "IPV6_TCLASS" },
	{ IPV6_V6ONLY, "IPV6_V6ONLY" },
	{ 0 }
};

struct dictionary at_flags_dict[] = {
	{ AT_FDCWD, "AT_FDCWD" },
	{ AT_EMPTY_PATH, "AT_EMPTY_PATH"},
	{ AT_SYMLINK_NOFOLLOW, "AT_SYMLINK_NOFOLLOW" },
	{ 0 }
};

struct dictionary fcntl_flags_dict[] = {
	{ F_SETFD, "F_SETFD" },
	{ F_SETFL, "F_SETFL" },
	{ F_GETFD, "F_GETFD" },
	{ F_GETFL, "F_GETFL" },
	{ F_SETLKW, "F_SETLKW" },
	{ F_DUPFD, "F_DUPFD" },
	{ F_SETLK, "F_SETLK" },
	{ 0 }
};

struct dictionary futex_op_dict[] = {
    { FUTEX_WAIT,                    "FUTEX_WAIT" },                    
    { FUTEX_WAKE,                    "FUTEX_WAKE" },                    
    { FUTEX_FD,                      "FUTEX_FD" },
    { FUTEX_REQUEUE,                 "FUTEX_REQUEUE" },                 
    { FUTEX_CMP_REQUEUE,             "FUTEX_CMP_REQUEUE" },             
    { FUTEX_WAKE_OP,                 "FUTEX_WAKE_OP" },                 
    { FUTEX_LOCK_PI,                 "FUTEX_LOCK_PI" },                 
    { FUTEX_UNLOCK_PI,               "FUTEX_UNLOCK_PI" },               
    { FUTEX_TRYLOCK_PI,              "FUTEX_TRYLOCK_PI" },              
    { FUTEX_WAIT_BITSET,             "FUTEX_WAIT_BITSET" },             
    { FUTEX_WAKE_BITSET,             "FUTEX_WAKE_BITSET" },             
    { FUTEX_WAIT_REQUEUE_PI,         "FUTEX_WAIT_REQUEUE_PI" },         
    { FUTEX_CMP_REQUEUE_PI,          "FUTEX_CMP_REQUEUE_PI" },          
    { FUTEX_LOCK_PI2,                "FUTEX_LOCK_PI2" },                
    { FUTEX_CLOCK_REALTIME,          "FUTEX_CLOCK_REALTIME" },

    /* private variants ( | FUTEX_PRIVATE_FLAG, +128 ) */
    { FUTEX_WAIT_PRIVATE,            "FUTEX_WAIT_PRIVATE" },            
    { FUTEX_WAKE_PRIVATE,            "FUTEX_WAKE_PRIVATE" },            
    { FUTEX_REQUEUE_PRIVATE,         "FUTEX_REQUEUE_PRIVATE" },         
    { FUTEX_CMP_REQUEUE_PRIVATE,     "FUTEX_CMP_REQUEUE_PRIVATE" },     
    { FUTEX_WAKE_OP_PRIVATE,         "FUTEX_WAKE_OP_PRIVATE" },         
    { FUTEX_LOCK_PI_PRIVATE,         "FUTEX_LOCK_PI_PRIVATE" },         
    { FUTEX_UNLOCK_PI_PRIVATE,       "FUTEX_UNLOCK_PI_PRIVATE" },       
    { FUTEX_TRYLOCK_PI_PRIVATE,      "FUTEX_TRYLOCK_PI_PRIVATE" },      
    { FUTEX_WAIT_BITSET_PRIVATE,     "FUTEX_WAIT_BITSET_PRIVATE" },     
    { FUTEX_WAKE_BITSET_PRIVATE,     "FUTEX_WAKE_BITSET_PRIVATE" },     
    { FUTEX_WAIT_REQUEUE_PI_PRIVATE, "FUTEX_WAIT_REQUEUE_PI_PRIVATE" }, 
    { FUTEX_CMP_REQUEUE_PI_PRIVATE,  "FUTEX_CMP_REQUEUE_PI_PRIVATE" },  
    { FUTEX_LOCK_PI2_PRIVATE,        "FUTEX_LOCK_PI2_PRIVATE" },        

    { 0 }
};

static inline int _search_flag(struct dictionary *dict, char *flag_str, uint64_t *flag_value_p)
{
	int final_value = 0, ret = 0;
	char *tmp_flag_str = strdup(flag_str);
	char *cur_flag = strtok(tmp_flag_str, "|");

	while (cur_flag) {
		int flag_value = 0;

		ret = str_to_val(cur_flag, dict, &flag_value);
		if (ret) {
			fprintf(stderr, "%s: unrecognized flag: %s\n", __func__, cur_flag);
			goto out;
		}
		final_value |= flag_value;

		cur_flag = strtok(NULL, "|");
	}

	*flag_value_p = final_value;

out:
	if (tmp_flag_str) free(tmp_flag_str);
	return ret;
}

int search_file_flag(char *flag_str, uint64_t *flag_value_p)
{
	return _search_flag(file_flags_dict, flag_str, flag_value_p);
}

int search_mode(char *flag_str, uint64_t *flag_value_p)
{
	return _search_flag(mode_dict, flag_str, flag_value_p);
}

int search_prot(char *flag_str, uint64_t *flag_value_p)
{
	return _search_flag(prot_dict, flag_str, flag_value_p);
}

int search_mmap_flag(char *flag_str, uint64_t *flag_value_p)
{
	return _search_flag(mmap_flags_dict, flag_str, flag_value_p);
}

int search_clone_flag(char *flag_str, uint64_t *flag_value_p)
{
	return _search_flag(clone_flags_dict, flag_str, flag_value_p);
}

int search_sock_flag(char *flag_str, uint64_t *flag_value_p)
{
	return _search_flag(sock_flags_dict, flag_str, flag_value_p);
}

int search_domain_flag(char *flag_str, uint64_t *flag_value_p)
{
	return _search_flag(domain_flags_dict, flag_str, flag_value_p);
}

int search_msg_flag(char *flag_str, uint64_t *flag_value_p)
{
	return _search_flag(msg_flags_dict, flag_str, flag_value_p);
}

int search_sop_flag(char *flag_str, uint64_t *flag_value_p)
{
	return _search_flag(sop_flags_dict, flag_str, flag_value_p);
}

int search_at_flag(char *flag_str, uint64_t *flag_value_p)
{
	return _search_flag(at_flags_dict, flag_str, flag_value_p);
}

int search_fcntl_flag(char *flag_str, uint64_t *flag_value_p)
{
	return _search_flag(fcntl_flags_dict, flag_str, flag_value_p);
}

int search_futex_op(char *flag_str, uint64_t *flag_value_p)
{
	return _search_flag(futex_op_dict, flag_str, flag_value_p);
}

int arg_str_to_val(char *str, int base, uint64_t *val_p)
{
	int ret = 0;
	char *endptr = NULL;
	uint64_t val = 0;

	val = strtoull(str, &endptr, base);
	if (!endptr || *endptr != '\0') {
		fprintf(stderr, "Invalid string: %s\n", str);
		ret = -1;
		goto out;
	}

	*val_p = val;

out:
	return ret;
}

static inline int extract_key_value(char *token, char *key, char *value)
{
	int ret = 0;
	char *k_start = token;
	char *brkp = strchr(token, '=');
	if (!brkp) {
		// token is not in key=value format
		*key = 0;
		*value = 0;

		ret = -1;
		goto out;
	}

	int k_len = brkp - k_start;

	memcpy(key, token, k_len);
	key[k_len] = 0;

	int v_len = strlen(token) - k_len - 1;
	memcpy(value, brkp + 1, v_len);
	value[v_len] = 0;

out:
	return ret;
}

int encode_saddr_struct(char *saddr, int addrlen, char **output)
{
	int i, ret = 0;
	char *hex_output = NULL;

	if (!output) {
		fprintf(stderr, "%s: invalid output buffer\n", __func__);
		ret = -1;
		goto out;
	}

	if (!addrlen) {
		char *null_str = strdup(NULL_STR);
		if (!null_str) {
			fprintf(stderr, "%s: strdup error\n", __func__);
			ret = -1;
			goto out;
		}
		*output = null_str;
		goto out;
	}

	if (addrlen < (int)sizeof(sa_family_t) || addrlen > (int)sizeof(struct sockaddr_storage)) {
		fprintf(stderr, "%s: Illegal sockaddr length\n", __func__);
		ret = -1;
		goto out;
	}

	hex_output = calloc(sizeof(struct sockaddr_storage)*2 + 1, sizeof(char));
	if (!hex_output) {
		fprintf(stderr, "%s: calloc failed\n", __func__);
		ret = -1;
		goto out;
	}

	char *hex_st = hex_output;
	struct sockaddr *_saddr = (struct sockaddr *)saddr;
	if (_saddr->sa_family == AF_UNIX) {
		/* AF_UNIX + encode sun_path until '\0' is met
			Reason this is treated separately:
			sun_path[108]; leftover byes will be filled with
			random numbers in RT, causing BF query failure.
		*/
		struct sockaddr_un *saddr_un = (struct sockaddr_un *)saddr;
		char *st = (char *)saddr_un;
		char *sun_path_p = saddr_un->sun_path;
		char *sun_end = st + addrlen;

		/* encode AF_UNIX */
		for (i = 0; i < (int)sizeof(sa_family_t); i++) {
			hex_st = hex_byte_pack_upper(hex_st, st[i]);
		}

		/* encode sun_path */
		while (sun_path_p < sun_end && *sun_path_p != '\0') {
			hex_st = hex_byte_pack_upper(hex_st, *sun_path_p);
			sun_path_p++;
		}
	} else {
		if (_saddr->sa_family == AF_INET) {
			struct sockaddr_in *saddr_in = (struct sockaddr_in *)_saddr;
			// sin_addr and sin_port is in network byte order --> host byte order
			int port_number = ntohs(saddr_in->sin_port);
			int min_dyn_port = 0;

			ret = get_dyn_port_range(&min_dyn_port, NULL);
			if (ret) {
				fprintf(stderr, "%s: failed to get dyn port range\n", __func__);
				ret = -1;
				goto out;
			}

			if (port_number >= min_dyn_port) {
				saddr_in->sin_port = 0;
			}
		}

		for (i = 0; i < addrlen; i++) {
			hex_st = hex_byte_pack_upper(hex_st, saddr[i]);
		}
	}

	*hex_st = '\0';
	/* one byte is encoded into two characters */
	*output = hex_output;

out:
	if (ret) free(hex_output);
	return ret;
}

/* FIXME: ipv6 skipped for now */
int encode_saddr_str(char *saddr_str, socklen_t addrlen, char **saddr_hex)
{
	char *st = saddr_str;
	int ret = 0;
	struct sockaddr_storage saddr = { 0 };

	if (!addrlen || !(strcmp(saddr_str, "NULL"))) {
		char *null_str = strdup(NULL_STR);
		if (!null_str) {
			fprintf(stderr, "%s: strdup error\n", __func__);
			ret = -1;
			goto out;
		}
		*saddr_hex = null_str;
		goto out;
	}

	if (addrlen > (int)sizeof(struct sockaddr_storage)) {
		fprintf(stderr, "%s: Illegal sockaddr length\n", __func__);
		ret = -1;
		goto out;
	}

	char org_str[INIT_BUF_LEN] = { 0 };
	int str_len = strlen(saddr_str);
	/* remove braces at beginning/end of the str if any */
	if (st[str_len-1] == '}') str_len--;
	if (*st == '{') st++;
	memcpy(org_str, st, str_len);

	char *token = strtok(org_str, ", ");
	while (token) {
		char key[32] = { 0 };
		char value[PATH_MAX] = { 0 };
		int ret_token = 0;

		ret_token = extract_key_value(token, key, value);

		if (ret_token == -1) {
			if (!strcmp(token, "inet_pton(AF_INET6")) {
//				char *start_ip = strtok(NULL, ", ");
//				char ipv6_addr[46] = { 0 };
				struct sockaddr_in6 *saddr_in6 = (struct sockaddr_in6 *)&saddr;
				struct in6_addr sin6_addr = { 0 };

//				if ((sscanf(start_ip, "\"%[^\"]", ipv6_addr)) != 1) {
//					fprintf(stderr, "%s: unable to acquire addr %s from %s\n",
//						__func__, ipv6_addr, token);
//					ret = -1;
//					goto out;
//				}
//				ipv6_addr[strlen(ipv6_addr)] = 0;
//
//				ret = inet_pton(AF_INET6, ipv6_addr, &sin6_addr);
//				if (!ret) {
//					fprintf(stderr, "%s: Invalid addr: %s\n", __func__, ipv6_addr);
//					ret = -1;
//					goto out;
//				}
				saddr_in6->sin6_addr = sin6_addr;
			}
		}
		else if (!strcmp(key, "sa_family")) {
			sa_family_t domain = 0;

			/* check from domain dictionary */
			ret = str_to_val(value, domain_flags_dict, &domain);
			if (ret) {
				fprintf(stderr, "%s: cannot identify address family: %s\n",
					__func__, value);
				ret = -1;
				goto out;
			}
			saddr.ss_family = domain;
		}
		else if (!strcmp(key, "sin_port") || !strcmp(key, "sin6_port")) {
			int port_number = 0;
			int min_dyn_port = 0, max_dyn_port = 0;

			ret = get_dyn_port_range(&min_dyn_port, &max_dyn_port);
			if (ret) {
				fprintf(stderr, "%s: failed to get dyn port range\n", __func__);
				ret = -1;
				goto out;
			}

			if ((sscanf(value, "htons(%d)", &port_number)) != 1) {
				fprintf(stderr, "%s: unable to acquire port number from %s\n",
					__func__, value);
				ret = -1;
				goto out;
			}

			if (saddr.ss_family == AF_INET) {
				struct sockaddr_in *saddr_in = (struct sockaddr_in *)&saddr;

				/* mask dynamic ports into 0
				   if (port_number >= min_dyn_port && port_number <= max_dyn_port)
					 until 65535: flask use port number > 60999 for accept4()
				*/
				if (port_number >= min_dyn_port) {
					saddr_in->sin_port = 0;
				}
				else {
					saddr_in->sin_port = htons(port_number);
				}
			}
			else if (saddr.ss_family == AF_INET6) {
				struct sockaddr_in6 *saddr_in6 = (struct sockaddr_in6 *)&saddr;

//				// mask dynamic ports into 0
//				if (port_number >= min_dyn_port) {
//					saddr_in6->sin6_port = 0;
//				}
//				else {
//					saddr_in6->sin6_port = htons(port_number);
//				}
				saddr_in6->sin6_port = 0;
			}
			else {
				fprintf(stderr, "%s: Invalid AF family %d to extract port number\n",
					 __func__, saddr.ss_family);
				ret = -1;
				goto out;
			}
		}
		else if (!strcmp(key, "sin_addr")) {
			char ip[64] = { 0 };
			struct sockaddr_in *saddr_in = (struct sockaddr_in *)&saddr;

			if ((sscanf(value, "inet_addr(\"%[^\"]\")", ip)) != 1) {
				fprintf(stderr, "%s: unable to acquire IP from %s\n",
					__func__, value);
				ret = -1;
				goto out;
			}
			inet_aton(ip, &saddr_in->sin_addr);
		}
		else if (!strcmp(key, "sun_path")) {
			char sun_path[120] = { 0 };
			struct sockaddr_un *saddr_un = (struct sockaddr_un *)&saddr;

			/* sun_path[108]: 107 + trailing \0 */
			if ((sscanf(value, "\"%107[^\"]\"", sun_path)) != 1) {
				fprintf(stderr, "%s: unable to acquire path from %s\n",
					__func__, value);
				ret = -1;
				goto out;
			}

			memcpy(saddr_un->sun_path, sun_path, strlen(sun_path));
		}
		else if (!strcmp(key, "nl_pid")) {
			struct sockaddr_nl *saddr_nl = (struct sockaddr_nl *)&saddr;
			pid_t pid = 0;

			// if 0 (kernel), keep is 0, if not zero (user), set to 1?
			if ((sscanf(value, "%u", &pid)) != 1) {
				fprintf(stderr, "%s: unable to acquire PID from %s\n",
					__func__, value);
				ret = -1;
				goto out;
			}

			if (pid) saddr_nl->nl_pid = 1; // user PID
			else saddr_nl->nl_pid = 0; // kernel
		}
		else if (!strcmp(key, "nl_groups")) {
			struct sockaddr_nl *saddr_nl = (struct sockaddr_nl *)&saddr;
			unsigned int nl_groups = 0;

			if ((sscanf(value, "%x", &nl_groups)) != 1) {
				fprintf(stderr, "%s: unable to extract group mask from %s\n",
					__func__, value);
				ret = -1;
				goto out;
			}
			saddr_nl->nl_groups = nl_groups;
		}
		else if (!strcmp(key, "sin6_flowinfo")) {
//			uint32_t flowinfo = 0;
//			struct sockaddr_in6 *saddr_in6 = (struct sockaddr_in6 *)&saddr;
//
//			if ((sscanf(value, "htonl(%u)", &flowinfo)) != 1) {
//				fprintf(stderr, "%s: unable to acquire flowinfo %s\n",
//					__func__, value);
//				ret = -1;
//				goto out;
//			}
//
//			saddr_in6->sin6_flowinfo = htonl(flowinfo);
		}
		else if (!strcmp(key, "sin6_scope_id")) {
			/* Skip 
 
			 FIXME: why setting scope ID cause SIGABRT malloc failed?
			because size of struct sockaddr is only 16 bytes,
			while struct sockaddr_in6 is 28 bytes.

			struct sockaddr_in6 *saddr_in6 = (struct sockaddr_in6 *)&saddr;
			char *endptr = NULL;

			saddr_in6->sin6_scope_id = (uint32_t)strtoul(value, &endptr, 10);
			*/
		}
		else {
			fprintf(stderr, "Unknown token: %s\n", token);
			ret = -1;
			goto out;
		}

		token = strtok(NULL, ", ");
	} 

	// encode into hex
	ret = encode_saddr_struct((char *)&saddr, addrlen, saddr_hex);
	if (ret) {
		fprintf(stderr, "%s: failed to enocde sockaddr\n", __func__);
		goto out;
	}

	ret = 0;

out:
	return ret;
}

int encode_sockmsg_saddr_str(char *msghdr, char **saddr_hex)
{
	int ret = 0;
	char *org_str = strdup(msghdr);
	char saddr_str[PATH_MAX*2] = { 0 };
	char *saddr_start = NULL, *saddr_end = NULL;
	char *len_start = NULL, *len_end = NULL;

	/* extract sockaddr length from msg_namelen= */
	char *len_k = "msg_namelen=";
	len_start = strstr(org_str, len_k);
	if (!len_start) {
		fprintf(stderr, "%s: failed to parse msghdr: %s\n", __func__, msghdr);
		ret = -1;
		goto out;
	}
	len_start += strlen(len_k);

	len_end = len_start;
	while (isdigit(*len_end)) len_end++;
	*len_end = '\0';
	socklen_t addrlen = strtol(len_start, NULL, 10);

	/* if addrlen is 0, msg_name would be NULL or non-existent */
	if (addrlen > 0) {
		/* extract sockaddr string from
			msg_name={sa_family=AF_INET, ...}
		*/
		char *name_k = "msg_name=";
		saddr_start = strstr(org_str, name_k);
		if (!saddr_start) {
			fprintf(stderr, "%s: wrong msghdr format: %s\n", __func__, msghdr);
			ret = -1;
			goto out;
		}
		/* either {saddr} or NULL */
		saddr_start += strlen(name_k);
	
		if (*saddr_start == '{') {
			/* skip the starting brace */
			saddr_start++;
			int len = 0;
	
			saddr_end = strchr(saddr_start, '}');
			if (!saddr_end) {
				fprintf(stderr, "%s: could not find ending brace: %s\n",
					__func__, saddr_start);
				ret = -1;
				goto out;
			}
			*saddr_end = '\0';
			len = saddr_end - saddr_start + 1; // include '\0'
	
			memcpy(saddr_str, saddr_start, len);
		
			/* encode using encode_saddr_str() */
			ret = encode_saddr_str(saddr_str, addrlen, saddr_hex);
			if (ret) {
				fprintf(stderr, "%s: failed to encode saddr: %s\n",
					__func__, msghdr);
				goto out;
			}
		} else {
			fprintf(stderr, "%s: wrong saddr string format?: %s\n",
				__func__, saddr_start);
			ret = -1;
			goto out;
		}
	} else if (!addrlen) {
		char *null_str = strdup(NULL_STR);
		if (!null_str) {
			fprintf(stderr, "%s: strdup error\n", __func__);
			ret = -1;
			goto out;
		}
		*saddr_hex = null_str;
		goto out;
	} else {
		fprintf(stderr, "%s: invalid msghdr: %s\n", __func__, msghdr);
		ret = -1;
		goto out;
	}

	ret = 0;

out:
	if (org_str) free(org_str);
	return ret;
}
