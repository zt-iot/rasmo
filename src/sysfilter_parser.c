#include <regex.h>
#include <ctype.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>

#include "sysfilter.h"
#include "rasmo_util.h"
#include "rasmo_sysname.h"

/* Regex */
#define regex_printerr(regex_addr, ret) do {\
	char msg[256] = { 0 }; \
	regerror(ret, regex_addr, msg, 256); \
	fprintf(stderr, "regexec failed: %s\n", msg); \
} while(0)

enum regex_pattern {
	REGEX_PATTERN_SYSCALL = 0,
	REGEX_PATTERN_SUCCESS,
	REGEX_PATTERN_ARGS,
	REGEX_PATTERN_EXECVE,
	REGEX_PATTERN_MMAP,
	REGEX_PATTERN_FNAME,
	REGEX_PATTERN_FINFO,
	REGEX_PATTERN_MSG_ID,
	REGEX_PATTERN_SADDR,
	REGEX_PATTERN_NUMBER
};

static struct regex_parser {
	int num_matches;
	char *pattern;
	regex_t regex;
} regex_parser[REGEX_PATTERN_NUMBER] = {
	[REGEX_PATTERN_SYSCALL] = {
		.num_matches = 1,
		.pattern = "syscall=([^[:space:]]+)"
	},
	[REGEX_PATTERN_SUCCESS] = {
		.num_matches = 1,
		.pattern = "success=([^[:space:]]+)"
	},
	[REGEX_PATTERN_ARGS] = {
		.num_matches = 4,
		.pattern = "a0=([^[:space:]]+) a1=([^[:space:]]+) a2=([^[:space:]]+) a3=([^[:space:]]+)"
	},
	[REGEX_PATTERN_EXECVE] = {
		.num_matches = 2,
		.pattern = "exe_a0=([^[:space:]]+) exe_opt=([^[:space:]]*)"
	},
	[REGEX_PATTERN_MMAP] = {
		.num_matches = 2,
		.pattern = "mmap_fd=([^[:space:]]+) mmap_flags=([^[:space:]]+)"
	},
	[REGEX_PATTERN_FNAME] = {
		.num_matches = 1,
		.pattern = "file=\"([^\"]*)\""
	},
	[REGEX_PATTERN_FINFO] = {
		.num_matches = 3,
		.pattern = "inode=([^[:space:]]+) dev=([^[:space:]]+) mode=([^[:space:]]+)"
	},
	[REGEX_PATTERN_MSG_ID] = {
		.num_matches = 1,
		.pattern = "msg_no=([^[:space:]]+)"
	},
	[REGEX_PATTERN_SADDR] = {
		.num_matches = 1,
		.pattern = "saddr=([^[:space:]]+)"
	},
};

int init_regex_parser(void)
{
	int i = 0, ret = 0;

	for (i = 0; i < REGEX_PATTERN_NUMBER; i++) {
		struct regex_parser *cur_parser = &regex_parser[i];
		regex_t *regex = &cur_parser->regex;
		char *pattern = cur_parser->pattern;

		ret = regcomp(regex, pattern, REG_EXTENDED);
		if (ret) {
			regex_printerr(regex, ret);
			goto out;
		}
	}

out:
	return ret;
}

static inline int parse_value(char *str, enum regex_pattern type, regmatch_t *matches)
{
	int num_matches = regex_parser[type].num_matches + 1;
	regex_t *regex = &regex_parser[type].regex;

	// match the string
	return regexec(regex, str, num_matches, matches, 0);
}

static inline int mask_saddr(char *saddr)
{
	int ret = 0;

	// acquire AF_INET (for now) port number from encoded saddr
	if (!strncmp(saddr, "0200", 4)) {
		char *port_start = saddr + 4;
		char port_str[5] = { 0 };
		char *endptr = NULL;

		int min_port = 0, max_port = 0;
		int port_number = 0;
		
		ret = get_dyn_port_range(&min_port, &max_port);
		if (ret) {
			fprintf(stderr, "%s: Failed to get port number\n", __func__);
			goto out;
		}

		memcpy(port_str, port_start, 4);

		port_number = strtol(port_str, &endptr, 16);
		if (*endptr != '\0') {
			fprintf(stderr, "%s: Invalid hex string: %s\n", __func__, port_str);
			ret = -1;
			goto out;
		}

		// if the port is dynamically allocated, mask the port number in saddr
		//if (port_number >= min_port && port_number <= max_port)
		if (port_number >= min_port) // bigger than 32768 (60999~65535 is also used by flask accept4)
			memcpy(saddr + 4, "0000", 4);
	}
	// AF_NETLINK mask PID
	else if (!strncmp(saddr, "1000", 4)) {
		char *pid_str = saddr + 8; // AF_FAMILY + padding ( 8 bytes in total)
		
		// if PID string not 0, mask user PID
		if (memcmp(pid_str, "00000000", 8)) {
			memcpy(pid_str, "01000000", 8);
		}
	}
	// FIXME: not checking AF_INET6 for now
	else if (!strncmp(saddr, "0A00", 4)) {
		char *st = saddr + 4;
		while (*st != '\0') {
			*st = '0'; st++;
		}
	}

out:
	return ret;
}

/* NOTE: match.rm_soand match.rm_eo may be -1 */
static inline int extract_from_matches(char *str, char *dst, size_t maxlen, regmatch_t match)
{
    int ret = 0;
    regoff_t st = match.rm_so;

    if (st >= 0) {
        size_t len = match.rm_eo - st;
        if (len < maxlen) {
            memcpy(dst, str + st, len);
            dst[len] = '\0';
        } else {
            ret = -1;
        }
    } else {
        dst[0] = '\0';
    }

    return ret;
}

static inline int extract_msg_id(char *str, int *id_p)
{
    int ret = 0;
    char buf[33] = { 0 };
    regmatch_t matches[2] = { 0 };

    ret = parse_value(str, REGEX_PATTERN_MSG_ID, matches);
    if (!ret) {
        ret = extract_from_matches(str, buf, sizeof(buf), matches[1]);
        if (!ret) *id_p = atoi(buf);
    }

    return ret;
}

static inline int extract_syscall_number(char *str, int *sysno_p)
{
    int ret = 0;
    char buf[33] = { 0 };
    regmatch_t matches[2] = { 0 };

    ret = parse_value(str, REGEX_PATTERN_SYSCALL, matches);
    if (!ret) {
        ret = extract_from_matches(str, buf, sizeof(buf), matches[1]);
        if (!ret) {
			int nb = atoi(buf);
			if (nb >= 0 && nb < SYSCALL_MAX) {
				*sysno_p = nb;
			}
			else {
				*sysno_p = -1;
				ret = -1;
			}
		}
    }

    return ret;
}

static inline int extract_syscall_status(char *str, int *status_p)
{
    int ret = 0;
    char buf[33] = { 0 };
    regmatch_t matches[2] = { 0 };

    ret = parse_value(str, REGEX_PATTERN_SUCCESS, matches);
    if (!ret) {
        ret = extract_from_matches(str, buf, sizeof(buf), matches[1]);
        if (!ret) {
			*status_p = atoi(buf);
		}
    }

    return ret;
}

static inline int extract_args(char *str, char args[4][64])
{
    int ret = 0, i;
    regmatch_t matches[5] = { 0 };

    ret = parse_value(str, REGEX_PATTERN_ARGS, matches);
    if (!ret) {
        for (i = 0; i < 4; i++) {
            ret = extract_from_matches(str, args[i], sizeof(args[i]), matches[i+1]);
            if (ret) break;
        }
    }

    return ret;
}

static inline int extract_file_md(char *str, struct rt_file_info *p)
{
    int ret = 0;
    regmatch_t matches[4] = { 0 };
    char inode[32] = { 0 }; char device[32] = { 0 }; char mode[32] = { 0 };

    if (!(parse_value(str, REGEX_PATTERN_FINFO, matches))) {
        if (!(extract_from_matches(str, inode, sizeof(inode), matches[1]))) {
            memcpy(p->inode, inode, sizeof(inode));
        } else {
			ret = -1;
			goto out;
		}

        if (!(extract_from_matches(str, device, sizeof(device), matches[2]))) {
            memcpy(p->device, device, sizeof(device));
        } else {
			ret = -1;
			goto out;
		}

        if (!(extract_from_matches(str, mode, sizeof(mode), matches[3]))) {
            memcpy(p->mode, mode, sizeof(mode));
        } else {
			ret = -1;
			goto out;
		}
    } else {
		ret = -1;
	}

out:
    return ret;
}

/* NULL_STR if no argument for execve */
static inline int extract_execve_option(char *str, struct rt_file_info *p,
                                        char *option, size_t option_len)
{
    int ret = 0;
    regmatch_t matches[3] = { 0 };

    if (!(parse_value(str, REGEX_PATTERN_EXECVE, matches))) {
        char buf[PATH_MAX] = { 0 }, abs_buf[PATH_MAX] = { 0 };

        if (!(extract_from_matches(str, buf, sizeof(buf), matches[1]))) {
            if (resolve_abs_path(buf, abs_buf)) {
				ret = -1;
				goto out;
			}
            p->exist = process_path(abs_buf, p->path);

            if (extract_file_md(str, p)) { ret = -1; goto out; }
            if (extract_from_matches(str, option, option_len, matches[2])) {
                ret = -1;
				goto out;
            }
        } else {
			ret = -1;
			goto out;
		}
    } else { ret = -1; }

out:
    return ret;
}

/* NOTE: libcamera-vid somehow tried to open an empty filename.
when it's empty no AUDIT_PATH record is emitted by Linux Audit */
static inline int extract_file_info(char *str, struct rt_file_info *i)
{
    int ret = 0;
    regmatch_t matches[2] = { 0 };
    struct rt_file_info *ptr = i;

    if (!(parse_value(str, REGEX_PATTERN_FNAME, matches))) {
        char p[PATH_MAX] = { 0 };
        if (!(extract_from_matches(str, p, sizeof(p), matches[1]))) {
            ptr->exist = process_path(p, ptr->path);
            if (!ptr->exist) {
				ret = 0;
				goto out;
			}
        } else {	
			ret = -1;
			goto out;
		}
		/* extract metadata if ptr->exist is true */
        if (extract_file_md(str, ptr)) {
			ret = -1;
			goto out;
		}
    } else {
		snprintf(ptr->path, PATH_MAX, "%s", NULL_STR);
		ptr->exist = 0;
	//	ret = -1;
	}

out:
    return ret;
}

/* NOTE:
connect() audit record example:
type=SOCKADDR msg=audit(1783335648.153:32765602): saddr=01002F7661722F72756E2F6E7363642F736F636B65740000A053A1AF7F00000080039FB07F000000B0FF1DD87F0000003C564B0000000000D085611F0000000020529BB07F000000F0FF1DD87F0000000C90490000000000584E8E0000000000F069611F00000000D085611F0000SADDR={ saddr_fam=local path=/var/run/nscd/socket }

when the socket type is AF_UNIX, there are trailing garbage in sun_path value.
need to extract the legitimate path and drop the garbage.

payload:

syscall=203 success=-1 a0=6 a1=7fffc26508 a2=6e a3=7fa7ca2040 saddr=01002F7661722F72756E2F6E7363642F736F636B6574000040474B00000000000300000000000000D065C2FF7F000000D0C4530000000000020000000000000000A2F691E573E671C065C2FF7F000000B48CA8A77F0000000060AFA77F000000C06AC2FF7F000000000000000000 file="/var/run/nscd/socket" inode=NULL dev=NULL mode=NULL

if AF_UNIX, encode from file field

*/
static inline int extract_saddr(char *str, char *saddr)
{
    int ret = 0;
    regmatch_t matches[2] = { 0 };
    char _saddr[PATH_MAX*2+1] = { 0 };

    if (!(parse_value(str, REGEX_PATTERN_SADDR, matches))) {
        if (!(extract_from_matches(str, _saddr, sizeof(_saddr), matches[1]))) {
            ret = mask_saddr(_saddr);
			if (ret) {
				fprintf(stderr, "%s: Failed to mask saddr: %s\n", __func__, str);
				goto out;
			}

			/* if AF_UNIX, extract file name */
			if (!strncmp(_saddr, "0100", 4)) {
				struct rt_file_info sock_file = { 0 };
				ret = extract_file_info(str, &sock_file);
				if (ret) {
					fprintf(stderr, "%s: failed to extract AF_UNIX info from %s\n", __func__, str);
					goto out;
				}
				char *path = sock_file.path;
				/* skip sa_family_t encoding */
				char *buf_st = _saddr + 4;

				/* encode sun_path */
				while (*path != '\0')
					buf_st = hex_byte_pack_upper(buf_st, *path++);

				*buf_st = '\0';
			}

            snprintf(saddr, PATH_MAX*2+1, "%s", _saddr);
        }
		else {
			 ret = -1;
		}
    }
	else {
		ret = -1;
	}

out:
    return ret;
}

static void token_arg_padding(char *arg)
{
	char *pattern = "ffffff9c";
	int len_arg = strlen(arg);
	int len_pat = 8;

	if ((len_arg == len_pat) && !memcmp(arg, pattern, len_arg)) {
		// padding with ffffffff
		char buf[64] = { 0 };
		int new_len = len_pat + 8;
		sprintf(buf, "ffffffff%s", pattern);
		buf[new_len] = '\0';

		memset(arg, 0, len_arg);
		memcpy(arg, buf, 64);
	}
}

/* call the parser if not null
	caller allocate space? */
int parse_record(char *payload, char *token)
{
	int ret = 0;
	int sysno = -1;

	ret = extract_syscall_number(payload, &sysno);
	if (ret) {
		fprintf(stderr, "%s: failed to identify sysno: %s\n", __func__, payload);
		ret = -1;
		goto out;
	}

	sysftr_func_ptr parser_func = get_parse_func(sysno, sysftr);
	if (parser_func) {
		ret = parser_func(payload, (char *)token);
		if (ret) {
			ret = -1;
			fprintf(stderr, "%s: Failed to parse sysno %d\n", __func__, sysno);
			goto out;
		}
	}
	else {
		ret = -1;
		fprintf(stderr, "No parsing function found for syscall %d\n", sysno);
		goto out;
	}

out:
	return ret;
}

static int encode_file_info(struct rt_file_info *info, char *header_output)
{
	int ret = 0, len = 0;
	char encode[FILE_HEADER_LEN] = { 0 };

	if (!info || !header_output) {
		fprintf(stderr, "%s: invalid argument\n", __func__);
		ret = -1;
		goto out;
	}

	char *inode = info->inode;
	char *device = info->device;
	char *mode = info->mode;
	char *path = info->path;
	int exist = info->exist;

	/* replace colon in device string */
	char device_form[32] = { 0 };
	snprintf(device_form, strlen(device) + 1, "%s", device);
	char *c = strchr(device_form, ':');
	if (c) *c = '-';

	len += snprintf(encode, PATH_MAX + 2, "%s", path);
	if (exist) {
		len += sprintf(encode+len, ":i=%s:d=%s:m=%s",
				inode, device_form, mode);
	}

	if (len >= PATH_MAX + 1024) {
		fprintf(stderr, "Invalid length of encoding: %d\n", len);
		ret = -1;
		goto out;
	}

	snprintf(header_output, FILE_HEADER_LEN, "%s", encode);

	ret = len;

out:
	return ret;
}

int statfs_sysftr_parse(char *payload, char *token)
{
	int ret = 0;
	struct rt_file_info file_info = { 0 };
	char output[INITIAL_BUFFER_LEN] = { 0 };
	char file_header[FILE_HEADER_LEN] = { 0 };
	int offset = 0;

	ret = extract_file_info(payload, &file_info);
	if (ret) {
		ret = -1;
		fprintf(stderr, "%s: failed to extract file info from %s\n", __func__, payload);
		goto out;
	}

	/* encode file header and return the number of characters encoded */
	ret = encode_file_info(&file_info, file_header);
	if (ret < 0) {
		ret = -1;
		fprintf(stderr, "%s: encode file info failed\n", __func__);
		goto out;
	}

	char args[4][64] = { 0 };
	extract_args(payload, args);

	offset = snprintf(output, INITIAL_BUFFER_LEN, "#%d:a0=%s",
					SYSNO(statfs), file_header);

	snprintf(token, offset+1, "%s", output);

	ret = 0;

out:
	return ret;
}

int faccessat_sysftr_parse(char *payload, char *token)
{
	int ret = 0;
	struct rt_file_info file_info = { 0 };
	char output[INITIAL_BUFFER_LEN] = { 0 };
	char file_header[FILE_HEADER_LEN] = { 0 };
	int offset = 0;

	ret = extract_file_info(payload, &file_info);
	if (ret) {
		ret = -1;
		fprintf(stderr, "%s: failed to extract file info from %s\n", __func__, payload);
		goto out;
	}

	/* encode file header and return the number of characters encoded */
	ret = encode_file_info(&file_info, file_header);
	if (ret < 0) {
		ret = -1;
		fprintf(stderr, "%s: encode file info failed\n", __func__);
		goto out;
	}

	char args[4][64] = { 0 };
	extract_args(payload, args);

	token_arg_padding(args[0]);

	offset = snprintf(output, INITIAL_BUFFER_LEN, "#%d:a0=%s:a1=%s:a2=%s",
						SYSNO(faccessat), args[0], file_header, args[2]);

	snprintf(token, offset+1, "%s", output);
	ret = 0;

out:
	return ret;
}

int openat_sysftr_parse(char *payload, char *token)
{
	int ret = 0;
	struct rt_file_info file_info = { 0 };
	char output[INITIAL_BUFFER_LEN] = { 0 };
	char file_header[FILE_HEADER_LEN] = { 0 };
	int offset = 0;

	ret = extract_file_info(payload, &file_info);
	if (ret) {
		ret = -1;
		fprintf(stderr, "%s: failed to extract file info from %s\n", __func__, payload);
		goto out;
	}

	/* encode file header and return the number of characters encoded */
	ret = encode_file_info(&file_info, file_header);
	if (ret < 0) {
		ret = -1;
		fprintf(stderr, "%s: encode file info failed\n", __func__);
		goto out;
	}

	char args[4][64] = { 0 };
	extract_args(payload, args);

	// for the case when AT_FDCWD is output into 32 bit value by Audit
	token_arg_padding(args[0]);
	offset = snprintf(output, INITIAL_BUFFER_LEN, "#%d:a0=%s:a1=%s:a2=%s",
						SYSNO(openat), args[0], file_header, args[2]);

	snprintf(token, offset+1, "%s", output);
	ret = 0;

out:
	return ret;
}

int readlinkat_sysftr_parse(char *payload, char *token)
{
	int ret = 0;
	struct rt_file_info file_info = { 0 };
	char output[INITIAL_BUFFER_LEN] = { 0 };
	char file_header[FILE_HEADER_LEN] = { 0 };
	int offset = 0;

	ret = extract_file_info(payload, &file_info);
	if (ret) {
		ret = -1;
		fprintf(stderr, "%s: failed to extract file info from %s\n", __func__, payload);
		goto out;
	}

	/* encode file header and return the number of characters encoded */
	ret = encode_file_info(&file_info, file_header);
	if (ret < 0) {
		ret = -1;
		fprintf(stderr, "%s: encode file info failed\n", __func__);
		goto out;
	}

	char args[4][64] = { 0 };
	extract_args(payload, args);

	token_arg_padding(args[0]);
	
	offset = snprintf(output, INITIAL_BUFFER_LEN, "#%d:a0=%s:a1=%s:a3=%s",
						SYSNO(readlinkat), args[0], file_header, args[3]);

	snprintf(token, offset+1, "%s", output);
	ret = 0;

out:
	return ret;
}

int newfstatat_sysftr_parse(char *payload, char *token)
{
	int ret = 0;
	struct rt_file_info file_info = { 0 };
	char output[INITIAL_BUFFER_LEN] = { 0 };
	char file_header[FILE_HEADER_LEN] = { 0 };
	int offset = 0;

	ret = extract_file_info(payload, &file_info);
	if (ret) {
		ret = -1;
		fprintf(stderr, "%s: failed to extract file info from %s\n", __func__, payload);
		goto out;
	}

	/* encode file header and return the number of characters encoded */
	ret = encode_file_info(&file_info, file_header);
	if (ret < 0) {
		ret = -1;
		fprintf(stderr, "%s: encode file info failed\n", __func__);
		goto out;
	}

	char args[4][64] = { 0 };
	extract_args(payload, args);

	token_arg_padding(args[0]);

	offset = snprintf(output, INITIAL_BUFFER_LEN, "#%d:a0=%s:a1=%s",
						SYSNO(newfstatat), args[0], file_header);
	snprintf(token, offset+1, "%s", output);
	ret = 0;

out:
	return ret;
}

int bind_sysftr_parse(char *payload, char *token)
{
	int ret = 0;
	char output[INITIAL_BUFFER_LEN] = { 0 };
	int offset = 0;
	char saddr[PATH_MAX * 2 + 1] = { 0 };

	ret = extract_saddr(payload, saddr);
	if (ret) {
		fprintf(stderr, "%s: failed to extract sockaddr from %s\n",
			__func__, payload );
		ret = -1;
		goto out;
	}

	char *st = (char *)output;
	char args[4][64] = { 0 };
	extract_args(payload, args);

	offset += sprintf(st+offset, "#%d:a1=%s:a2=%s", SYSNO(bind), saddr, args[2]);
	snprintf(token, offset+1, "%s", output);
	ret = 0;

out:
	return ret;
}

int connect_sysftr_parse(char *payload, char *token)
{
	int ret = 0;
	char output[INITIAL_BUFFER_LEN] = { 0 };
	int offset = 0;
	char saddr[PATH_MAX * 2 + 1] = { 0 };

	ret = extract_saddr(payload, saddr);
	if (ret) {
		fprintf(stderr, "%s: failed to extract sockaddr from %s\n",
			__func__, payload );
		ret = -1;
		goto out;
	}

	char *st = (char *)output;
	char args[4][64] = { 0 };
	extract_args(payload, args);

	offset += sprintf(st+offset, "#%d:a1=%s:a2=%s", SYSNO(connect), saddr, args[2]);
	snprintf(token, offset+1, "%s", output);
	ret = 0;

out:
	return ret;
}

int recvmsg_sysftr_parse(char *payload, char *token)
{
	int ret = 0;
	char output[INITIAL_BUFFER_LEN] = { 0 };
	int offset = 0;
	char saddr[PATH_MAX * 2 + 1] = { 0 };

	ret = extract_saddr(payload, saddr);
	if (ret) {
		fprintf(stderr, "%s: failed to extract sockaddr from %s\n",
			__func__, payload );
		ret = -1;
		goto out;
	}

	char *st = (char *)output;
	char args[4][64] = { 0 };
	extract_args(payload, args);

	offset += sprintf(st+offset, "#%d:a1=%s:a2=%s", SYSNO(recvmsg), saddr, args[2]);
	snprintf(token, offset+1, "%s", output);
	ret = 0;

out:
	return ret;
}

int sendmmsg_sysftr_parse(char *payload, char *token)
{
	int ret = 0;
	char output[INITIAL_BUFFER_LEN] = { 0 };
	int offset = 0;
	char saddr[PATH_MAX * 2 + 1] = { 0 };

	ret = extract_saddr(payload, saddr);
	if (ret) {
		fprintf(stderr, "%s: failed to extract sockaddr from %s\n",
			__func__, payload );
		ret = -1;
		goto out;
	}

	char *st = (char *)output;
	char args[4][64] = { 0 };
	extract_args(payload, args);

	offset += sprintf(st+offset, "#%d:a1=%s:a3=%s", SYSNO(sendmmsg), saddr, args[3]);
	snprintf(token, offset+1, "%s", output);
	ret = 0;

out:
	return ret;
}

/* NOTE: Linux audit does not output SADDR for sendto(),
   this function cause rt error msg to check against tokens,
   if sendto is in the audit rule */
int sendto_sysftr_parse(char *payload, char *token)
{
	/* FIXME: do nothing for now */
	int ret = 0;
	(void)payload;
	(void)token;

	/*
	char output[INITIAL_BUFFER_LEN] = { 0 };
	int offset = 0;
	char saddr[PATH_MAX * 2 + 1] = { 0 };

	ret = extract_saddr(payload, saddr);
	if (ret) {
		fprintf(stderr, "%s: failed to extract sockaddr from %s\n",
			__func__, payload );
		ret = -1;
		goto out;
	}

	char *st = (char *)output;
	char args[4][64] = { 0 };
	extract_args(payload, args);

	offset += sprintf(st+offset, "#%d:a3=%s:a4=%s", SYSNO(sendto), args[3], saddr);
	snprintf(token, offset+1, "%s", output);
	ret = 0;
out:
*/
	return ret;
}

int execve_sysftr_parse(char *payload, char *token)
{
	int ret = 0;
	struct rt_file_info file_info = { 0 };
	char output[INITIAL_BUFFER_LEN] = { 0 };
	char file_header[FILE_HEADER_LEN] = { 0 };
	int offset = 0;
	char *execve_args = NULL;
	long arg_max = sysconf(_SC_ARG_MAX);
	if (arg_max < 0) {
		perror("sysconf failed:");
		ret = -1;
		goto out;
	}

	execve_args = calloc(arg_max, sizeof(char));
	if (!execve_args) {
		fprintf(stderr, "%s: failed to allocate mem\n", __func__);
		ret = -1;
		goto out;
	}

	ret = extract_execve_option(payload, &file_info, execve_args, arg_max);
	if (ret) {
		fprintf(stderr, "%s: failed to extract execve info: %s\n", __func__, payload);
		ret = -1;
		goto out;
	}

	/* encode file header and return the number of characters encoded */
 	ret = encode_file_info(&file_info, file_header);
	if (ret < 0) {
		ret = -1;
		fprintf(stderr, "%s: encode file info failed\n", __func__);
		goto out;
	}

	offset = snprintf(output, INITIAL_BUFFER_LEN-offset, "#%d:a0=%s:a1=%s",
					SYSNO(execve), file_header, execve_args);

	snprintf(token, offset+1, "%s", output);

	ret = 0;

out:
	free(execve_args);

	return ret;
}
