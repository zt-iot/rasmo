#include <stdio.h>
#include <limits.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <seccomp.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <sys/sysmacros.h>

#include "rasmo_util.h"
#include "seccomp_util.h"
#include "seccomp_common.h"
#include "seccomp_parser.h"
#include "rasmo_sysname.h"

#define NUM_ARGS 6

static int extract_arg_fd(char *arg, uint64_t *output)
{
	int ret = 0;
	char *tmp_arg = NULL;

	if (!arg) {
		fprintf(stderr, "Empty argument string\n");
		goto out;
	}

	tmp_arg = strdup(arg);

	// a0: AT_FDCWD or a file descriptor or -1
	if (isdigit(*tmp_arg) || (*tmp_arg == '-')) {
		// file descriptor (extract file descriptor only for now)
		uint64_t value = 0;

		/* strace --decode-fds */
		char *tmp = strchr(tmp_arg, '<');
		if (tmp) { *tmp = '\0'; } 

		ret = arg_str_to_val(tmp_arg, 10, &value);
		if (ret) {
			fprintf(stderr, "%s: failed to convert fd str %s\n", __func__, tmp_arg);
			goto out;
		}

		*output = value;
	}
	else if (!(strcmp(tmp_arg, "AT_FDCWD"))) {
		*output = AT_FDCWD;	
	}
	else {
		fprintf(stderr, "%s: invalid FD arg: %s\n", __func__, tmp_arg);
		ret = -1;
		goto out;
	}
	
out:
	free(tmp_arg);
	return ret;
}

int extract_file_info(char *fname, struct file_info **info)
{
	int ret = 0;
	struct stat file_stat = { 0 };
	struct file_info *f_info = NULL;
	int file_exist = 1;

	// always generate a file info object even if the call failed (?)
	f_info = calloc(1, sizeof(struct file_info));
	if (!f_info) {
		fprintf(stderr, "%s: failed to calloc\n", __func__);
		ret = -1;
		goto out;
	}

	file_exist = process_path(fname, f_info->path);
	if (!file_exist) goto out;

	ret = stat(f_info->path, &file_stat);
	if (!ret) {
		f_info->inode = file_stat.st_ino;
		f_info->dev_major = major(file_stat.st_dev);
		f_info->dev_minor = minor(file_stat.st_dev);
		f_info->mode = file_stat.st_mode;
	}
	else {
		file_exist = 0;
	}

	ret = 0;

out:
	if (f_info) f_info->file_exist = file_exist;
	*info = f_info;

	return ret;
}

static int extract_arguments(char *str, char *arg_list[])
{
	int i, _num_args = 0; 
	char *args_tmp[NUM_ARGS] = { 0 };
	char *tmp_str = strdup(str);
	int offset = 0, ret = 0;

	if (!arg_list) {
		fprintf(stderr, "%s: Invalid arguments: %s\n", __func__, str);
		goto out;
	}

	// find the start and end of the argument list
	char *start_args = strchr(tmp_str, '(');
	char *end_args = NULL, *cur_arg = NULL;

	// get the start & end pointer of the argument list
	if (start_args) {
		start_args++; // ignore the starting parenthesis
		int arg_len = strlen(start_args);

		// some lines return error value containing (...)
		offset = find_last_char(start_args, arg_len, '=');
		if (offset < 0) {
			fprintf(stderr, "Error parsing line: %s (No return value found)\n", tmp_str);
			ret = -1;
			goto out;
		}
		else {
			int end_args_offset = find_last_char(start_args, offset, ')');
			if (end_args_offset < 0) {
				fprintf(stderr, "Error parsing: %s (No matching parenthesis)\n", tmp_str);
				ret = -1;
				goto out;
			}
			end_args = start_args + end_args_offset;
		}

		if (start_args == end_args) {
			goto out;
		}

		cur_arg = start_args;
		*end_args = '\0';
	}
	else {
		fprintf(stderr, "Error parsing line: %s (line incomplete?)\n", tmp_str);
		ret = -1;
		goto out;
	}

	/* start extracting */
	while (cur_arg != end_args) {
		char *start = cur_arg;
		int brace_cnt = 0, bracket_cnt = 0;

		// a structure argument
		if (*cur_arg == '{') {
			start++;
			brace_cnt++;
			while (brace_cnt) {
				cur_arg++;
				if (*cur_arg == '{') brace_cnt++;
				if (*cur_arg == '}') brace_cnt--;
			} // find the matching closing brace
		}
		else if (*cur_arg == '[') { // an array or bitset
			start++;
			bracket_cnt++;
			while (bracket_cnt) {
				cur_arg++;
				if (*cur_arg == '[') bracket_cnt++;
				if (*cur_arg == ']') bracket_cnt--;
			}
		}
		else if (*cur_arg == '"') { // a string. remove the quotes
			start++;
			do { cur_arg++; } while (*cur_arg != '"');
		}
		else if ((*cur_arg == ' ' ||
				*cur_arg == ',' ||
				*cur_arg == '.') && (cur_arg != end_args))
		{
			cur_arg++; continue;
		}
		/* normal argument */
		else {
			while ((*cur_arg != ',') && (cur_arg != end_args)) cur_arg++;
		}

		if (cur_arg == start) {
			args_tmp[_num_args++] = strdup(NULL_STR);
		}
		else {
			args_tmp[_num_args++] = strndup(start, cur_arg-start);
		}

		if (cur_arg != end_args) cur_arg++;
		if (_num_args == NUM_ARGS) break;
	}

	for (i = 0; i < _num_args; i++) {
		arg_list[i] = args_tmp[i];
	}	

out:
	if (tmp_str) free(tmp_str);
	return ret;
}

// default: check syscall number only
int default_parse(char *trace, void *output)
{
	(void) trace;
	struct profile_syscall *profile = (struct profile_syscall *) output;

	profile->action = ALLOW;
	profile->num_args = 0;
	profile->args = NULL; // skip args
	profile->token = NULL;

	return 0;
}

static inline void free_arglist(char **arg_list)
{
	int i;
	for (i = 0; i < NUM_ARGS; i++) {
		if (arg_list[i]) free(arg_list[i]);
	}
}

/* section: ALLOW but with args */
int clone_parse(char *trace, void *output)
{
	int ret = 0, num_args = 1;
	struct profile_syscall *profile = (struct profile_syscall *) output;
	char *arglist[NUM_ARGS] = { 0 };

	ret = extract_arguments(trace, arglist);
	if (ret) {
		fprintf(stderr, "%s: failed to parse args of %s\n", __func__, trace);
		goto out;
	}

	profile->action = ALLOW;
	profile->num_args = num_args;

	struct syscall_arg *tmp_args = calloc(num_args, sizeof(struct syscall_arg));
	if (!tmp_args) {
		fprintf(stderr, "%s failed to alloc memory: %s\n", __func__, strerror(errno));
		ret = -1;
		goto out;
	}

	/* a0: flags for clone() system call
	   a1 in strace */
	uint64_t value = 0;
	struct syscall_arg *a0 = tmp_args;
	char *a0_str = arglist[1];
	char flags_str[4096] = { 0 };

	sscanf(a0_str, "flags=%s", flags_str);

	ret = search_clone_flag(flags_str, &value);
	if (ret) {
		fprintf(stderr, "%s: unrecognized arg %s \n", __func__, a0_str);
		goto out;
	}

	a0->idx = 0;
	a0->type = VAL_ARG;
	a0->value = value;
	a0->op = SCMP_CMP_EQ;

	profile->args = tmp_args;

out:
	free_arglist(arglist);
	return ret;
}

int futex_parse(char *trace, void *output)
{
	int ret = 0, num_args = 1;
	struct profile_syscall *profile = (struct profile_syscall *) output;
	char *arglist[NUM_ARGS] = { 0 };

	ret = extract_arguments(trace, arglist);
	if (ret) {
		fprintf(stderr, "%s: failed to parse args of %s\n", __func__, trace);
		goto out;
	}

	profile->action = ALLOW;
	profile->num_args = num_args;

	struct syscall_arg *tmp_args = calloc(num_args, sizeof(struct syscall_arg));
	if (!tmp_args) {
		fprintf(stderr, "%s failed to alloc memory: %s\n", __func__, strerror(errno));
		ret = -1;
		goto out;
	}

	// a1: futex op
	uint64_t futex_op = 0;
	struct syscall_arg *a1 = &tmp_args[0];
	char *a1_str = arglist[1];

	ret = search_futex_op(a1_str, &futex_op);
	if (ret) {
		fprintf(stderr, "%s: failed to parse: %s\n", __func__, a1_str);
		ret = -1;
		goto out;
	}
	
	a1->idx = 1;
	a1->type = VAL_ARG;
	a1->value = futex_op;
	a1->op = SCMP_CMP_EQ;

	profile->args = tmp_args;
	ret = 0;

out:
	free_arglist(arglist);
	return ret;
}

int mmap_parse(char *trace, void *output)
{
	int ret = 0, num_args = 2;
	struct profile_syscall *profile = (struct profile_syscall *) output;
	char *arglist[NUM_ARGS] = { 0 };

	ret = extract_arguments(trace, arglist);
	if (ret) {
		fprintf(stderr, "%s: failed to parse args of %s\n", __func__, trace);
		goto out;
	}

	profile->action = ALLOW;
	profile->num_args = num_args;

	struct syscall_arg *tmp_args = calloc(num_args, sizeof(struct syscall_arg));
	if (!tmp_args) {
		fprintf(stderr, "%s failed to alloc memory: %s\n", __func__, strerror(errno));
		ret = -1;
		goto out;
	}

	// a2: prot
	uint64_t prot_value = 0;
	char *prot_str = arglist[2];
	struct syscall_arg *a2 = &tmp_args[0];

	a2->idx = 2;
	a2->type = VAL_ARG;
	a2->op = SCMP_CMP_EQ;

	ret = search_prot(prot_str, &prot_value);
	if (ret) {
		fprintf(stderr, "%s: unrecognized arg %s \n", __func__, prot_str);
		goto out;
	}
	a2->value = prot_value;

	// a3: flags
	uint64_t flag_value = 0;
	char *flags_str = arglist[3];
	struct syscall_arg *a3 = &tmp_args[1];

	a3->idx = 3;
	a3->type = VAL_ARG;
	a3->op = SCMP_CMP_EQ;

	ret = search_mmap_flag(flags_str, &flag_value);
	if (ret) {
		fprintf(stderr, "%s: unrecognized arg %s \n", __func__, flags_str);
		goto out;
	}
	a3->value = flag_value;

	profile->args = tmp_args;

out:
	free_arglist(arglist);
	return ret;
}

int ioctl_parse(char *trace, void *output)
{
	int ret = 0, num_args = 1;
	struct profile_syscall *profile = (struct profile_syscall *) output;
	char *arglist[NUM_ARGS] = { 0 };

	ret = extract_arguments(trace, arglist);
	if (ret) {
		fprintf(stderr, "%s: failed to parse args of %s\n", __func__, trace);
		goto out;
	}

	profile->action = ALLOW;
	profile->num_args = num_args;

	struct syscall_arg *tmp_args = calloc(num_args, sizeof(struct syscall_arg));
	if (!tmp_args) {
		fprintf(stderr, "%s failed to alloc memory: %s\n", __func__, strerror(errno));
		ret = -1;
		goto out;
	}
	
	// a1: ioctl op value
	uint64_t value = 0;
	tmp_args->idx = 1;
	tmp_args->type = VAL_ARG;
	tmp_args->op = SCMP_CMP_EQ;

	ret = arg_str_to_val(arglist[1], 16, &value);
	if (ret) {
		fprintf(stderr, "Failed to parse %s arg %s\n", trace, arglist[1]);
		goto out;
	}
	tmp_args->value = value;

	profile->args = tmp_args;

out:
	free_arglist(arglist);
	return ret;
}

int socket_parse(char *trace, void *output)
{
	int ret = 0, num_args = 2;
	struct profile_syscall *profile = (struct profile_syscall *) output;
	char *arglist[NUM_ARGS] = { 0 };

	ret = extract_arguments(trace, arglist);
	if (ret) {
		fprintf(stderr, "%s: failed to parse args of %s\n", __func__, trace);
		goto out;
	}

	profile->action = ALLOW;
	profile->num_args = num_args;

	struct syscall_arg *tmp_args = calloc(num_args, sizeof(struct syscall_arg));
	if (!tmp_args) {
		fprintf(stderr, "%s failed to alloc memory: %s\n", __func__, strerror(errno));
		ret = -1;
		goto out;
	}

	// a0: domain 
	struct syscall_arg *a0 = &tmp_args[0];
	a0->idx = 0;
	a0->type = VAL_ARG;
	a0->op = SCMP_CMP_EQ;

	uint64_t a0_flag = 0;
	ret = search_domain_flag(arglist[0], &a0_flag);
	if (ret) {
		fprintf(stderr, "%s: unrecognized arg %s \n", __func__, arglist[0]);
		goto out;
	}
	a0->value = a0_flag;

	// a1: type
	struct syscall_arg *a1 = &tmp_args[1];
	a1->idx = 1;
	a1->type = VAL_ARG;
	a1->op = SCMP_CMP_EQ;

	uint64_t a1_flag = 0;
	ret = search_sock_flag(arglist[1], &a1_flag);
	if (ret) {
		fprintf(stderr, "%s: unrecognized arg %s \n", __func__, arglist[1]);
		goto out;
	}
	a1->value = a1_flag;

	// a2: protocol (?) maybe later

	profile->args = tmp_args;

out:
	free_arglist(arglist);
	return ret;
}

int recvfrom_parse(char *trace, void *output)
{
	int ret = 0, num_args = 1;
	struct profile_syscall *profile = (struct profile_syscall *) output;
	char *arglist[NUM_ARGS] = { 0 };

	ret = extract_arguments(trace, arglist);
	if (ret) {
		fprintf(stderr, "%s: failed to parse args of %s\n", __func__, trace);
		goto out;
	}

	profile->action = ALLOW;
	profile->num_args = num_args;

	// fill in args for checking
	struct syscall_arg *tmp_args = calloc(num_args, sizeof(struct syscall_arg));
	if (!tmp_args) {
		fprintf(stderr, "%s: Failed to alloc memory: %s\n",
			__func__, strerror(errno));
		ret = -1;
		goto out;
	}

	// a3: flags
	struct syscall_arg *a3 = &tmp_args[0];
	uint64_t flags = 0;

	ret = search_msg_flag(arglist[3], &flags);
	if (ret) {
		fprintf(stderr, "Failed to parse %s\n", arglist[3]);
		ret = -1;
		goto out;
	}

	a3->idx = 3;
	a3->type = VAL_ARG;
	a3->op = SCMP_CMP_EQ;

	a3->value = flags;
	
	/*
		a4 saddr: not all protocols provide saddr for messages
	*/
	profile->args = tmp_args;
	ret = 0;

out:
	free_arglist(arglist);
	return ret;
}
/* end section: ALLOW */

/*
	encode token: 
*/
static int encode_token(struct profile_syscall *profile)
{
	int ret = 0, i;
	int sysno = profile->sysno;
	int num_args = profile->num_args;

	int encode_len = 0;
	char buf[INIT_BUF_LEN] = { 0 };
	struct syscall_arg *args = profile->args;

	ret = snprintf(buf+encode_len, sizeof(buf)-encode_len, "#%d", sysno);
	encode_len += ret;

	for (i = 0; i < num_args; i++) {
		struct syscall_arg *cur_arg = &args[i];

		if (cur_arg->type == VAL_ARG) {
			ret = snprintf(buf+encode_len, sizeof(buf)-encode_len,
				":a%d=%lx", cur_arg->idx, cur_arg->value);
		} else {
			ret = snprintf(buf+encode_len, sizeof(buf)-encode_len,
				":a%d=%s", cur_arg->idx, cur_arg->string);
		}
		encode_len += ret;
	}

	buf[encode_len] = '\0';
	char *tmp = strdup(buf);
	if (!tmp) {
		perror("strdup failed:");
		ret = -1;
		goto out;
	}

	profile->token = tmp;

	ret = 0;

out:
	return ret;
}

static int encode_fn_args(struct file_info *info, char **arg)
{
	char buf[INIT_BUF_LEN] = { 0 };
	int ret = 0, encode_len = 0;

	/* only file header for now */
	if (info) {
		encode_len = snprintf(buf, PATH_MAX, "%s", info->path);

		if (info->file_exist) {
			ret = snprintf(buf+encode_len, sizeof(buf)-encode_len, ":i=%ld:d=%02x-%02x:m=%#o",
				info->inode, info->dev_major, info->dev_minor, info->mode);
			if (ret <= 0) {
				fprintf(stderr, "Failed to encode file info %s\n", info->path);
				ret = -1;
				goto out;
			}
			encode_len += ret;
		}
	}

	char *tmp = strdup(buf);
	if (!tmp) {
		perror("strdup failed:");
		ret = -1;
	}

	*arg = tmp;
	ret = 0;

out:
	return ret;
}

/* section: NOTIFY */
int openat_parse(char *trace, void *output)
{
	int ret = 0, num_args = 3;
	struct profile_syscall *profile = (struct profile_syscall *) output;
	char *arglist[NUM_ARGS] = { 0 };

	ret = extract_arguments(trace, arglist);
	if (ret) {
		fprintf(stderr, "%s: failed to parse args of %s\n", __func__, trace);
		goto out;
	}

	// fill in args for checking
	struct syscall_arg *tmp_args = calloc(num_args, sizeof(struct syscall_arg));
	if (!tmp_args) {
		perror("calloc failed:");
		ret = -1;
		goto out;
	}

	// a0: fd or AT_FDCWD
	struct syscall_arg *a0 = &tmp_args[0];
	char *a0_str = arglist[0];

	a0->idx = 0;
	a0->type = VAL_ARG;
	a0->op = SCMP_CMP_EQ;

	ret = extract_arg_fd(a0_str, &a0->value);
	if (ret) {
		fprintf(stderr, "Not able to extract FD: %s\n", a0_str);
		goto out;
	}

	// a1: filename --> extract file metadata
	struct syscall_arg *a1 = &tmp_args[1];

	a1->idx = 1;
	a1->type = PTR_ARG;
	a1->op = -1;

	// extract file metadata
	struct file_info *info = NULL;
	ret = extract_file_info(arglist[1], &info);
	if (ret) {
		fprintf(stderr, "Failed to extract file info of %s\n", arglist[1]);
		goto out;
	}

	ret = encode_fn_args(info, &a1->string);
	if (ret) {
		fprintf(stderr, "%s: failed to encode file arg\n", __func__);
		goto out;
	}

	// a2: flags
	struct syscall_arg *a2 = &tmp_args[2];
	a2->idx = 2;
	a2->type = VAL_ARG;
	a2->op = SCMP_CMP_EQ;

	// get flag value
	uint64_t flag_value = 0;
	ret = search_file_flag(arglist[2], &flag_value);
	if (ret) {
		fprintf(stderr, "Failed to parse %s\n", arglist[2]);
		ret = -1;
		goto out;
	}
	a2->value = flag_value;
	
	// assign syscall args profile
	profile->action = NOTIFY;
	profile->num_args = num_args;
	profile->args = tmp_args;

	ret = encode_token(profile);
	if (ret) {
		fprintf(stderr, "%s: token encoding failed\n", __func__);
		goto out;
	}

	ret = 0;

out:
	free_arglist(arglist);
	return ret;
}

/* TODO: how to check options?
	for now, we get app options from global variable exe_args
*/
extern int num_exeargs;
extern char **exe_args;
/* TODO: what if multiple execve in the trace like Dropbear SSH? */
int execve_parse(char *trace, void *output)
{
	int ret = 0, num_args = 2;
	struct profile_syscall *profile = (struct profile_syscall *) output;
	char *arglist[NUM_ARGS] = { 0 };

	ret = extract_arguments(trace, arglist);
	if (ret) {
		fprintf(stderr, "%s: failed to parse args of %s\n", __func__, trace);
		goto out;
	}

	// fill in args for checking
	struct syscall_arg *tmp_args = calloc(num_args, sizeof(struct syscall_arg));
	if (!tmp_args) {
		fprintf(stderr, "%s: failed to allocate memory: %s\n", __func__, strerror(errno));
		ret = -1;
		goto out;
	}

	// a0: file
	struct syscall_arg *a0 = &tmp_args[0];
	const char *pathname = arglist[0];
	char resolved_path[PATH_MAX] = { 0 };

	ret = resolve_abs_path(pathname, resolved_path);
	if (ret) {
		fprintf(stderr, "%s: failed to resolve path: %s\n", __func__, pathname);
		goto out;
	}

	struct file_info *info = NULL;
	
	a0->idx = 0;
	a0->type = PTR_ARG;
	a0->op = -1;

	// extract file metadata
	ret = extract_file_info(resolved_path, &info);
	if (ret) {
		fprintf(stderr, "%s: Failed to extract file info of %s\n", __func__, resolved_path);
		goto out;
	}

	ret = encode_fn_args(info, &a0->string);
	if (ret) {
		fprintf(stderr, "%s: failed to encode file arg\n", __func__);
		goto out;
	}

	/* encode arg string */
	struct syscall_arg *a1 = &tmp_args[1];

	a1->idx = 1;
	a1->type = PTR_ARG;
	a1->op = -1;

	/* FIXME: currently simply copied into a buffer for simplicity */
	int len = 0, bufsize = 0, i;

	for (i = 1; i < num_exeargs; i++) {
		bufsize += strlen(exe_args[i]);
	}

	if (!bufsize) {
		a1->string = strdup(NULL_STR);
	}
	else {
		char *args = calloc(++bufsize, sizeof(char));
		if (!args) {
			fprintf(stderr, "%s: failed to allocate buf\n", __func__);
			ret = -1;
			goto out;
		}
	
		for (i = 1; i < num_exeargs; i++) {
			len += snprintf(args+len, bufsize-len,"%s", exe_args[i]);
		}
		args[len] = '\0';
		a1->string = args;
	}

	profile->action = NOTIFY;
	profile->num_args = num_args;
	profile->args = tmp_args;

	ret = encode_token(profile);
	if (ret) {
		fprintf(stderr, "%s: token encoding failed\n", __func__);
		goto out;
	}

	ret = 0;

out:
	free_arglist(arglist);
	return ret;
}

int faccessat_parse(char *trace, void *output)
{
	int ret = 0, num_args = 3;
	struct profile_syscall *profile = (struct profile_syscall *) output;
	char *arglist[NUM_ARGS] = { 0 };

	ret = extract_arguments(trace, arglist);
	if (ret) {
		fprintf(stderr, "%s: failed to parse args of %s\n", __func__, trace);
		goto out;
	}

	// fill in args for checking
	struct syscall_arg *tmp_args = calloc(num_args, sizeof(struct syscall_arg));
	if (!tmp_args) {
		perror("Failed to alloc memory for openat: ");
		ret = -1;
		goto out;
	}

	// a0: fd or AT_FDCWD
	struct syscall_arg *a0 = &tmp_args[0];
	char *a0_str = arglist[0];

	a0->idx = 0;
	a0->type = VAL_ARG;
	a0->op = SCMP_CMP_EQ;

	ret = extract_arg_fd(a0_str, &a0->value);
	if (ret) {
		fprintf(stderr, "Not able to extract FD: %s\n", a0_str);
		goto out;
	}

	// a1: filename --> extract file metadata
	struct syscall_arg *a1 = &tmp_args[1];

	a1->idx = 1;
	a1->type = PTR_ARG;
	a1->op = -1;

	// extract file metadata
	struct file_info *info = NULL;
	char *a1_str = arglist[1];
	ret = extract_file_info(a1_str, &info);
	if (ret) {
		fprintf(stderr, "Failed to extract file info of %s\n", a1_str);
		goto out;
	}

	ret = encode_fn_args(info, &a1->string);
	if (ret) {
		fprintf(stderr, "%s: failed to encode file arg\n", __func__);
		goto out;
	}

	// a2: flags
	struct syscall_arg *a2 = &tmp_args[2];
	char *a2_str = arglist[2];

	a2->idx = 2;
	a2->type = VAL_ARG;
	a2->op = SCMP_CMP_EQ;

	// get mode value
	uint64_t mode_value = 0;
	ret = search_mode(a2_str, &mode_value);
	if (ret) {
		fprintf(stderr, "Failed to parse %s\n", a2_str);
		ret = -1;
		goto out;
	}
	a2->value = mode_value;
	
	profile->action = NOTIFY;
	profile->num_args = num_args;
	profile->args = tmp_args;

	ret = encode_token(profile);
	if (ret) {
		fprintf(stderr, "%s: token encoding failed\n", __func__);
		goto out;
	}

	ret = 0;

out:
	free_arglist(arglist);
	return ret;
}

int statfs_parse(char *trace, void *output)
{
	int ret = 0, num_args = 1;
	struct profile_syscall *profile = (struct profile_syscall *) output;
	char *arglist[NUM_ARGS] = { 0 };

	ret = extract_arguments(trace, arglist);
	if (ret) {
		fprintf(stderr, "%s: failed to parse args of %s\n", __func__, trace);
		goto out;
	}

	// fill in args for checking
	struct syscall_arg *tmp_args = calloc(num_args, sizeof(struct syscall_arg));
	if (!tmp_args) {
		perror("Failed to alloc memory for openat: ");
		ret = -1;
		goto out;
	}

	// a0: path
	struct syscall_arg *a0 = &tmp_args[0];
	char *a0_str = arglist[0];

	a0->idx = 0;
	a0->type = PTR_ARG;
	a0->op = -1;

	// extract file metadata
	struct file_info *info = NULL;
	ret = extract_file_info(a0_str, &info);
	if (ret) {
		fprintf(stderr, "Failed to extract file info of %s\n", a0_str);
		goto out;
	}

	ret = encode_fn_args(info, &a0->string);
	if (ret) {
		fprintf(stderr, "%s: failed to encode file arg\n", __func__);
		goto out;
	}

	profile->action = NOTIFY;
	profile->num_args = num_args;
	profile->args = tmp_args;

	ret = encode_token(profile);
	if (ret) {
		fprintf(stderr, "%s: token encoding failed\n", __func__);
		goto out;
	}

	ret = 0;

out:
	free_arglist(arglist);
	return ret;
}

int newfstatat_parse(char *trace, void *output)
{
	int ret = 0, num_args = 2;
	struct profile_syscall *profile = (struct profile_syscall *) output;
	char *arglist[NUM_ARGS] = { 0 };

	ret = extract_arguments(trace, arglist);
	if (ret) {
		fprintf(stderr, "%s: failed to parse args of %s\n", __func__, trace);
		goto out;
	}

	// fill in args for checking
	struct syscall_arg *tmp_args = calloc(num_args, sizeof(struct syscall_arg));
	if (!tmp_args) {
		perror("calloc failed:");
		ret = -1;
		goto out;
	}

	// a0: dirfd
	struct syscall_arg *a0 = &tmp_args[0];
	char *a0_str = arglist[0];

	a0->idx = 0;
	a0->type = VAL_ARG;
	a0->op = SCMP_CMP_EQ;

	ret = extract_arg_fd(a0_str, &a0->value);
	if (ret) {
		fprintf(stderr, "Not able to extract FD: %s\n", a0_str);
		goto out;
	}

	// a1: extract file metadata
	struct file_info *info = NULL;
	struct syscall_arg *a1 = &tmp_args[1];
	char *a1_str = arglist[1];

	a1->idx = 1;
	a1->type = PTR_ARG;
	a1->op = -1;

	ret = extract_file_info(a1_str, &info);
	if (ret) {
		fprintf(stderr, "Failed to extract file info of %s\n", a0_str);
		goto out;
	}

	ret = encode_fn_args(info, &a1->string);
	if (ret) {
		fprintf(stderr, "%s: failed to encode file arg\n", __func__);
		goto out;
	}

	profile->action = NOTIFY;
	profile->num_args = num_args;
	profile->args = tmp_args;

	ret = encode_token(profile);
	if (ret) {
		fprintf(stderr, "%s: token encoding failed\n", __func__);
		goto out;
	}

	ret = 0;

out:
	free_arglist(arglist);
	return ret;
}

int readlinkat_parse(char *trace, void *output)
{
	int ret = 0, num_args = 3;
	struct profile_syscall *profile = (struct profile_syscall *) output;
	char *arglist[NUM_ARGS] = { 0 };

	ret = extract_arguments(trace, arglist);
	if (ret) {
		fprintf(stderr, "%s: failed to parse args of %s\n", __func__, trace);
		goto out;
	}

	// fill in args for checking
	struct syscall_arg *tmp_args = calloc(num_args, sizeof(struct syscall_arg));
	if (!tmp_args) {
		perror("calloc failed:");
		ret = -1;
		goto out;
	}

	// a0: dirfd
	struct syscall_arg *a0 = &tmp_args[0];
	char *a0_str = arglist[0];

	a0->idx = 0;
	a0->type = VAL_ARG;
	a0->op = SCMP_CMP_EQ;

	ret = extract_arg_fd(a0_str, &a0->value);
	if (ret) {
		fprintf(stderr, "Not able to extract FD: %s\n", a0_str);
		goto out;
	}

	// a1: path
	struct file_info *info = NULL;
	struct syscall_arg *a1 = &tmp_args[1];
	char *a1_str = arglist[1];

	a1->idx = 1;
	a1->type = PTR_ARG;
	a1->op = -1;

	ret = extract_file_info(a1_str, &info);
	if (ret) {
		fprintf(stderr, "Failed to extract file info of %s\n", a0_str);
		goto out;
	}

	ret = encode_fn_args(info, &a1->string);
	if (ret) {
		fprintf(stderr, "%s: failed to encode file arg\n", __func__);
		goto out;
	}

	// a3: bufsize
	struct syscall_arg *a3 = &tmp_args[2];
	char *a3_str = arglist[3];
	uint64_t bufsize = 0;

	a3->idx = 3;
	a3->type = VAL_ARG;
	a3->op = SCMP_CMP_EQ;

	ret = arg_str_to_val(a3_str, 10, &bufsize);
	if (ret) {
		fprintf(stderr, "%s: failed to parse: %s\n", __func__, a3_str);
		ret = -1;
		goto out;
	}
	a3->value = bufsize;

	profile->action = NOTIFY;
	profile->num_args = num_args;
	profile->args = tmp_args;

	ret = encode_token(profile);
	if (ret) {
		fprintf(stderr, "%s: token encoding failed\n", __func__);
		goto out;
	}

	ret = 0;

out:
	free_arglist(arglist);
	return ret;
}

static int _sock_call_parse(char *trace, void *output, int with_flag)
{
	int ret = 0, num_args = (with_flag)? 3 : 2;
	struct profile_syscall *profile = (struct profile_syscall *) output;
	char *arglist[NUM_ARGS] = { 0 };

	ret = extract_arguments(trace, arglist);
	if (ret) {
		fprintf(stderr, "%s: failed to parse args of %s\n", __func__, trace);
		goto out;
	}

	// fill in args for checking
	struct syscall_arg *tmp_args = calloc(num_args, sizeof(struct syscall_arg));
	if (!tmp_args) {
		fprintf(stderr, "%s: Failed to alloc memory: %s\n",
			__func__, strerror(errno));
		ret = -1;
		goto out;
	}

	// a2: socklen 
	struct syscall_arg *a2 = &tmp_args[1];
	a2->idx = 2;
	a2->type = VAL_ARG;
	a2->op = SCMP_CMP_EQ;

	uint64_t sock_len = 0;
	ret = arg_str_to_val(arglist[2], 10, &sock_len);
	if (ret) {
		fprintf(stderr, "%s: failed to parse: %s\n", __func__, arglist[2]);
		ret = -1;
		goto out;
	}
	a2->value = sock_len;

	// a1: SOCKADDR
	struct syscall_arg *a1 = &tmp_args[0];
	char *saddr_str = NULL;

	a1->idx = 1;
	a1->type = PTR_ARG;
	a1->op = -1;

	ret = encode_saddr_str(arglist[1], sock_len, &saddr_str);
	if (ret) {
		fprintf(stderr, "%s: failed to parse: %s\n", __func__, arglist[1]);
		ret = -1;
		goto out;
	}

	a1->string = saddr_str;

	// a3: flags if any
	if (with_flag) {
		struct syscall_arg *a3 = &tmp_args[2];
		char *flags_str = arglist[3];
		uint64_t flags = 0;

		a3->idx = 3;
		a3->type = VAL_ARG;
		a3->op = SCMP_CMP_EQ;
	
		ret = search_sock_flag(flags_str, &flags);
		if (ret) {
			fprintf(stderr, "Failed to parse %s\n", flags_str);
			ret = -1;
			goto out;
		}
		a3->value = flags;
	}

	profile->action = NOTIFY;
	profile->num_args = num_args;
	profile->args = tmp_args;

	ret = encode_token(profile);
	if (ret) {
		fprintf(stderr, "%s: token encoding failed\n", __func__);
		goto out;
	}

	ret = 0;

out:
	free_arglist(arglist);
	return ret;
}

int bind_parse(char *trace, void *output)
{
	return _sock_call_parse(trace, output, 0);
}

int connect_parse(char *trace, void *output)
{
	return _sock_call_parse(trace, output, 0);
}

int sendto_parse(char *trace, void *output)
{
	int ret = 0, num_args = 2;
	struct profile_syscall *profile = (struct profile_syscall *) output;
	char *arglist[NUM_ARGS] = { 0 };

	ret = extract_arguments(trace, arglist);
	if (ret) {
		fprintf(stderr, "%s: failed to parse args of %s\n", __func__, trace);
		goto out;
	}

	// fill in args for checking
	struct syscall_arg *tmp_args = calloc(num_args, sizeof(struct syscall_arg));
	if (!tmp_args) {
		fprintf(stderr, "%s: Failed to alloc memory: %s\n",
			__func__, strerror(errno));
		ret = -1;
		goto out;
	}

	// a3: flags
	struct syscall_arg *a3 = &tmp_args[0];
	char *flags_str = arglist[3];
	uint64_t flags = 0;

	a3->idx = 3;
	a3->type = VAL_ARG;
	a3->op = SCMP_CMP_EQ;

	ret = search_msg_flag(flags_str, &flags);
	if (ret) {
		fprintf(stderr, "Failed to parse %s\n", flags_str);
		ret = -1;
		goto out;
	}
	a3->value = flags;

	// a5: addrlen
	//struct syscall_arg *a5 = &tmp_args[2];
	char *addrlen_str = arglist[5];
	uint64_t addrlen = 0;

//	a5->idx = 5;
//	a5->type = VAL_ARG;
//	a5->op = SCMP_CMP_EQ;

	ret = arg_str_to_val(addrlen_str, 10, &addrlen);
	if (ret) {
		fprintf(stderr, "%s: failed to parse: %s\n", __func__, addrlen_str);
		ret = -1;
		goto out;
	}
//	a5->value = addrlen;

	// a4: saddr
	struct syscall_arg *a4 = &tmp_args[1];
	char *saddr_arg_str = arglist[4];
	char *saddr_str = NULL;

	a4->idx = 4;
	a4->type = PTR_ARG;
	a4->op = -1;

	ret = encode_saddr_str(saddr_arg_str, addrlen, &saddr_str);
	if (ret) {
		fprintf(stderr, "%s: failed to parse: %s\n", __func__, saddr_arg_str);
		ret = -1;
		goto out;
	}
	a4->string = saddr_str;	

	profile->action = NOTIFY;
	profile->num_args = num_args;
	profile->args = tmp_args;

	ret = encode_token(profile);
	if (ret) {
		fprintf(stderr, "%s: token encoding failed\n", __func__);
		goto out;
	}

	ret = 0;

out:
	free_arglist(arglist);
	return ret;
}

int recvmsg_parse(char *trace, void *output)
{
	int ret = 0, num_args = 2;
	struct profile_syscall *profile = (struct profile_syscall *) output;
	char *arglist[NUM_ARGS] = { 0 };

	ret = extract_arguments(trace, arglist);
	if (ret) {
		fprintf(stderr, "%s: failed to parse args of %s\n", __func__, trace);
		goto out;
	}

	// fill in args for checking
	struct syscall_arg *tmp_args = calloc(num_args, sizeof(struct syscall_arg));
	if (!tmp_args) {
		fprintf(stderr, "%s: Failed to alloc memory: %s\n",
			__func__, strerror(errno));
		ret = -1;
		goto out;
	}

	/* a1: struct msghdr */
	struct syscall_arg *a1 = &tmp_args[0];
	char *msghdr = arglist[1];
	char *saddr_str = NULL;

	a1->idx = 1;
	a1->type = PTR_ARG;
	a1->op = -1;

	/* extract saddr from struct hdrmsg */
	ret = encode_sockmsg_saddr_str(msghdr, &saddr_str);
	if (ret) {
		fprintf(stderr, "%s: Failed to encode: %s\n", __func__, msghdr);
		ret = -1;
		goto out;
	}
	a1->string = saddr_str;

	/* a2: flags */
	struct syscall_arg *a2 = &tmp_args[1];
	a2->idx = 2;
	a2->type = VAL_ARG;
	a2->op = SCMP_CMP_EQ;

	uint64_t flag_value = 0;
	ret = search_msg_flag(arglist[2], &flag_value);
	if (ret) {
		fprintf(stderr, "Failed to parse %s\n", arglist[2]);
		ret = -1;
		goto out;
	}
	a2->value = flag_value;

	profile->action = NOTIFY;
	profile->num_args = num_args;
	profile->args = tmp_args;

	ret = encode_token(profile);
	if (ret) {
		fprintf(stderr, "%s: token encoding failed\n", __func__);
		goto out;
	}

	ret = 0;

out:
	free_arglist(arglist);
	return ret;
}

/* TODO: how to deal with multiple msghdrs? 
	here assumes n is 1 for now;
	Need to check how strace reports mmsghdr when n > 1
*/
int sendmmsg_parse(char *trace, void *output)
{
	int ret = 0, num_args = 2;
	struct profile_syscall *profile = (struct profile_syscall *) output;
	char *arglist[NUM_ARGS] = { 0 };

	ret = extract_arguments(trace, arglist);
	if (ret) {
		fprintf(stderr, "%s: failed to parse args of %s\n", __func__, trace);
		goto out;
	}

	// fill in args for checking
	struct syscall_arg *tmp_args = calloc(num_args, sizeof(struct syscall_arg));
	if (!tmp_args) {
		fprintf(stderr, "%s: Failed to alloc memory: %s\n",
			__func__, strerror(errno));
		ret = -1;
		goto out;
	}

	// a1: mmsghdr
	struct syscall_arg *a1 = &tmp_args[0];
	char *msghdr = arglist[1];
	char *saddr_str = NULL;

	a1->idx = 1;
	a1->type = PTR_ARG;
	a1->op = -1;

	/* extract saddr */
	ret = encode_sockmsg_saddr_str(msghdr, &saddr_str);
	if (ret) {
		fprintf(stderr, "%s: Failed to encode: %s\n", __func__, msghdr);
		ret = -1;
		goto out;
	}
	a1->string = saddr_str;

	// a3: flags
	struct syscall_arg *a3 = &tmp_args[1];
	char *flag_str = arglist[3];
	uint64_t flag_value = 0;

	a3->idx = 3;
	a3->type = VAL_ARG;
	a3->op = SCMP_CMP_EQ;

	ret = search_msg_flag(flag_str, &flag_value);
	if (ret) {
		fprintf(stderr, "Failed to parse %s\n", flag_str);
		ret = -1;
		goto out;
	}
	a3->value = flag_value;

	profile->action = NOTIFY;
	profile->num_args = num_args;
	profile->args = tmp_args;

	ret = encode_token(profile);
	if (ret) {
		fprintf(stderr, "%s: token encoding failed\n", __func__);
		goto out;
	}

	ret = 0;

out:
	free_arglist(arglist);
	return ret;
}

/* start parsing the trace */
int do_parse(char *trace, int sysno, void *p)
{
	int ret = 0;

	if (!trace || !p || sysno < 0) {
		fprintf(stderr, "%s: Invalid argument\n", __func__);
		ret = -1;
		goto out;
	}

	struct profile_syscall *profile = (struct profile_syscall *) p;
	profile_func_ptr parse_func = get_parse_func(sysno, profile);

	if (parse_func) {
		ret = parse_func(trace, profile);
		if (ret) {
			fprintf(stderr, "Failed to define sysc %d profile\n", sysno);
			goto out;
		}
	}
	else {
		ret = default_parse(trace, profile);
		if (ret) {
			fprintf(stderr, "Failed to define sysc %d profile\n", sysno);
			goto out;
		}
	}

out:
	return ret;
}

