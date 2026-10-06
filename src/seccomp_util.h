#ifndef _SECCOMP_UTIL_H_
#define _SECCOMP_UTIL_H_

#include <sys/socket.h>
#include <string.h>

#define INIT_BUF_LEN 65536

struct dictionary {
	uint32_t val;
	const char *str;
};

#define val_to_str(value, dict) ({\
	const char *_str = NULL; int i = 0;\
	while (1) {\
		if (dict[i].str == NULL) break;\
		if ((uint32_t)value == dict[i].val) {\
			_str = dict[i].str; break;\
		}\
		i++;\
	}\
	_str;\
})

#define str_to_val(string, dict, vp) ({\
	uint32_t __value = 0; int i = 0, ret = 0;\
	const char *__s = (string);\
	struct dictionary *__d = (dict);\
	while (1) {\
		if (__d[i].str == NULL) { ret = -1; break; }\
		if (!strcmp(__d[i].str, __s)) {\
			__value = __d[i].val; break;\
		}\
		i++;\
	}\
	*(vp) = __value; \
	ret;\
})


#define extract_app_name(path, fname_buf) ({\
	char *last_slash = strrchr(path, '/');\
	if (last_slash) {\
		int i = 0; last_slash++; \
		while (*last_slash != '\0') { fname_buf[i++] = *last_slash++; } \
		fname_buf[i] = '\0';\
	} else {\
		int len = strlen(path);\
		memcpy(fname_buf, path, strlen(path));\
		fname_buf[len] = '\0';\
	}\
})

int search_file_flag(char *, uint64_t *);
int search_mode(char *, uint64_t *);
int search_prot(char *, uint64_t *);
int search_mmap_flag(char *, uint64_t *);
int search_clone_flag(char *, uint64_t *);
int search_sock_flag(char *, uint64_t *);
int search_domain_flag(char *, uint64_t *);
int search_msg_flag(char *, uint64_t *);
int search_futex_op(char *, uint64_t *);

int arg_str_to_val(char *, int, uint64_t *);

int encode_saddr_str(char *, socklen_t, char **);
int encode_saddr_struct(char *, int, char **);
int encode_sockmsg_saddr_str(char *, char **);

#endif
