#include <dirent.h>
#include <sys/types.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/stat.h>
#include <seccomp.h>
#include <linux/version.h>

#include "rasmo_sysname.h"
#include "rasmo_util.h"
#include "seccomp_json.h"
#include "seccomp_parser.h"
#include "seccomp_util.h"
#include "seccomp_common.h"

#define LINE_LEN ( 65536 * 4 )

/* for execve */
int num_exeargs = 0;
char **exe_args = NULL;

static inline void free_profile(int num, struct profile_syscall *list)
{
	int i;

	if (!list) return;

	for (i = 0; i < num; i++) {
		struct profile_syscall *cur = &list[i];
		struct syscall_arg *args = cur->args;

		if (args) {
			int num = cur->num_args, j = 0;
			for (j = 0; j < num; j++) {
				struct syscall_arg *cur_arg = &args[j];
				if (cur_arg->type == PTR_ARG) {
					free(cur_arg->string);
				}
			}
			free(args);
		}
		free(cur->token);
	}

	free(list);
}

// count the number of files
static inline int get_num_threads(char *path)
{
	struct dirent *entp = NULL;
	DIR *dp = NULL;
	int num = 0, ret = 0;

	dp = opendir(path);
	if (!dp) {
		perror("Failed to open strace log directory");
		ret = -errno;
		goto out;
	}

	// iterate through all the files in the output dir
	while ((entp = readdir(dp)) != NULL) {
		char *name = entp->d_name;
		// skip ., .*, and ..
		if (name[0] != '.') {
			char *last_dot = strrchr(name, '.');
			// skip the output file that does not contain pid
			if (last_dot) num++;
		}
	}

	if (dp) closedir(dp);

	ret = num;

out:
	return ret;
}

static inline int get_num_lines(char *path)
{
	int ret = 0, num = 0;
	FILE *fp = NULL;
	fp = fopen(path, "r");
	if (!fp) {
		perror("Failed to open the file:");
		ret = -errno;
		goto out;
	}

	// valid lines only
	char tmp[LINE_LEN] = { 0 };
	while ((fgets(tmp, LINE_LEN, fp))) {
		if (strstr(tmp, " ????")	||
			strstr(tmp, "--- ") 	||
			strstr(tmp, "+++ ") 	||
			strstr(tmp, "<unfinished ...>"))
			continue;

		num++;
	}

	if (fp) fclose(fp);
	ret = num;

out:
	return ret;
}

static inline int extract_syscall_number(char *line, int *sysno)
{
	int ret = 0, _sysno = 0;
	char close = 0;
	char *start = strstr(line, "[");
	if (!start) {
		ret = -1;
		fprintf(stderr, "Invalid trace format: %s\n", line);
		goto out;
	}

	ret = sscanf(start, "[%d %c", &_sysno, &close);
	if (ret != 2 || close != ']') {
		ret = -1;
		fprintf(stderr, "Failed to extract syscall number from %s\n", start);
		goto out;
	}

	*sysno = _sysno;
	ret = 0;

out:
	return ret;
}


/* 
	cannot add filters to individual threads anyway, just run strace and output 
	the syscall trace of the whole process.

	cannot do kcpd either. No point to do it for now cuz filters cannot be changed
	after installed.

	output: 
	* length of the parsed syscall list;
	* parsed syscall list
*/
int output_syscall_list(char *output_dir, int *len, struct profile_syscall **strace_list)
{
	int ret = 0, total_lines = 0;
	struct dirent *entp = NULL;
	DIR *dp = NULL;
	FILE *fp = NULL;

	struct profile_syscall *output_list = NULL,
						   *cur_list = NULL; 

	char strace_path[PATH_MAX] = { 0 };

	/* strace_path must have been created, error if not exist */
	snprintf(strace_path, PATH_MAX, "%s/strace", output_dir);

	int num_threads = get_num_threads(strace_path);
	if (num_threads <= 0) {
		fprintf(stderr, "Could not find strace thread output\n");
		ret = -1;
		goto out;
	}

	/* put all straces of threads into the same struct */
	dp = opendir(strace_path);
	if (!dp) {
		fprintf(stderr, "Failed to open dir %s\n", strace_path);
		ret = -1;
		goto out;
	}

	// iterate through all the files in the output dir
	while ((entp = readdir(dp)) != NULL) {
		char *name = entp->d_name;
		// skip ., .., and hidden files
		if (name[0] == '.')
			continue;

		int num_lines = 0;

		// skip the output file that does not contain pid
		char path[PATH_MAX] = { 0 };
		snprintf(path, PATH_MAX, "%s/%s", strace_path, name);

		num_lines = get_num_lines(path);
		if (num_lines <= 0) {
			fprintf(stderr, "Invalid trace file %s\n", path);
			ret = -1;
			goto out;
		}
		total_lines += num_lines;

		// expand the memory for the new file
		char *tmp = realloc(output_list, sizeof(struct profile_syscall) * total_lines);
		if (!tmp) {
			if (output_list) free(output_list);
			perror("Failed to re-allocate memory for the file buffer\n");
			ret = -1;
			goto out;
		}
		output_list = (struct profile_syscall *) tmp;
		cur_list = output_list + total_lines - num_lines;
		memset(cur_list, 0, sizeof(struct profile_syscall) * num_lines);

		// read traces in the file
		fp = fopen(path, "r");
		if (!fp) {
			perror("Failed to open the file:");
			ret = -errno;
			goto out;
		}

		// extract timestamp and syscall number in each line
		// of the current file
		char line[LINE_LEN] = { 0 };
		int line_no = 0;

		/*
			parse each line
		*/
		while ((fgets(line, LINE_LEN, fp))) {
			// skip signal output
			if (
				strstr(line, " ????")	||
				strstr(line, "--- ") 	||
				strstr(line, "+++ ") 	||
				strstr(line, "<unfinished ...>"))
				continue;
			int sysno = 0;
			struct profile_syscall *cur_line = &cur_list[line_no++];

			ret = extract_syscall_number(line, &sysno);
			if (ret) {
				fprintf(stderr, "%s: extract sysno failed\n", __func__);
				goto out;
			}

			cur_line->sysno = sysno;

			/* parse the line */
			ret = do_parse(line, sysno, cur_line);
			if (ret) {
				fprintf(stderr, "Failed to parse call: %d\n", sysno);
				goto out;
			}
		}

		if (fp) fclose(fp);
		fp = NULL;
	}

	*len = total_lines;
	*strace_list = output_list;
	ret = 0;

out:
	if (ret) free(output_list);
	if (fp) fclose(fp);
	if (dp) closedir(dp);
	return ret;
}

/*
	compare the arguments of two syscall profile structs
	1: not the same
	0: the same
	-1: error
*/
static int compare_profile(struct profile_syscall *p1, struct profile_syscall *p2)
{
	int ret = 0;

	if (!p1 || !p2) {
		fprintf(stderr, "%s: invalid arguments\n", __func__);
		ret = -1;
		goto out;
	}

	if (p1->sysno != p2->sysno) {
		ret = 1; goto out;
	}

	/* same sysno */
	int num_args1 = p1->num_args;
	int num_args2 = p2->num_args;

	if (!num_args1 && !num_args2 ) {
		ret = 0; goto out;
	}

	if (num_args1 == num_args2) {
		struct syscall_arg *args1 = p1->args;
		struct syscall_arg *args2 = p2->args;
		int k, result = 0;
		
		for (k = 0; k < num_args1; k++) {
			if (args1[k].type == VAL_ARG) {
				if (!(memcmp(&args1[k], &args2[k],
					sizeof(struct syscall_arg)))) {
					result++;
				}
			}
		}

		if (result == num_args1) {
			/* all the scalar args are the same */
			ret = 0; 
		}
		else {
			/* some args are different */
			ret = 1; 
		}
	}
	else {
		/* how can two profiles for the same sysno have different number of args? */
		fprintf(stderr, "parsing was wrong for %d\n", p1->sysno);
		ret = -1;
	}

out:
	return ret;
}

/**
	dedup strace list and sort into two lists:

	1. ALLOW
	 * If args ==  NULL
	 * if args != NULL

	2. NOTIFY
*/
static int filter_profile_list(struct profile_syscall *list, int len,
	struct profile_syscall **output, int *output_len,
	struct profile_syscall **notify_out, int *notify_len)
{
	int ret = 0, i, j;
	int num_all = 0, num_notify = 0;
	struct profile_syscall *overall_syscalls = NULL,
						   *notify_syscalls = NULL;

	if (!list || !len) {
		fprintf(stderr, "%s: invalid arguments\n", __func__);
		ret = -1;
		goto out;
	}

	// alloc memory for the two tmp lists
	overall_syscalls = calloc(len, sizeof(struct profile_syscall));
	if (!overall_syscalls) {
		perror("Failed to allocate mem for overall list:");
		ret = -1;
		goto out;
	}

	notify_syscalls = calloc(len, sizeof(struct profile_syscall));
	if (!notify_syscalls) {
		perror("Failed to allocate mem for notify list:");
		ret = -1;
		goto out;
	}

	/*
		dedup: only put into the overall list if new:
		overall_syscalls dedup list maintains:
		1. ALLOW without args
		2. ALLOW with different args
		3. NOTIFY
	*/
	for (i = 0; i < len; i++) {
		struct profile_syscall *cur = &list[i];

		// check if the syscall profile already exist in the list
		for (j = 0; j < num_all; j++) {
			struct profile_syscall *tmp = &overall_syscalls[j];

			if (cur->sysno == tmp->sysno) {
#ifdef SECCOMP_USER_NOTIF_FLAG_CONTINUE
				if (cur->action == ALLOW) {
					ret = compare_profile(cur, tmp);
					if (!ret) break;
					else if (ret < 0) goto out; // error
				}

				if (cur->action == NOTIFY) break;
#else
				ret = compare_profile(cur, tmp);
				if (!ret) break;
				else if (ret < 0) goto out; // error
#endif
			}
		}

		// if didn't find the same entry, add to the list
		if (j == num_all) {
			overall_syscalls[num_all++] = *cur;
		}

		// if NOTIFY, also add to a separate list if not exists
		if (cur->action == NOTIFY) {
			// check if the same notify entry already exists
			for (j = 0; j < num_notify; j++) {
				struct profile_syscall *tmp = &notify_syscalls[j];

				if (!strcmp(cur->token, tmp->token)) break;
			}

			// add to the list if no same entry found
			if (j == num_notify) {
				notify_syscalls[num_notify++] = *cur;
			}
		}
	}

	char *tmp = NULL;
	tmp = realloc(overall_syscalls, sizeof(struct profile_syscall) * num_all);
	if (!tmp) {
		perror("Failed to resize overall syscall list:");
		ret = -1;
		goto out;
	}
	overall_syscalls = (struct profile_syscall *)tmp;

	tmp = realloc(notify_syscalls, sizeof(struct profile_syscall) * num_notify);
	if (!tmp) {
		perror("Failed to resize BF syscall list:");
		ret = -1;
		goto out;
	}
	notify_syscalls = (struct profile_syscall *)tmp;

	*output = overall_syscalls;
	*output_len = num_all;
	*notify_out = notify_syscalls;
	*notify_len = num_notify;

	ret = 0;

out:
	if (ret) {
		free(overall_syscalls);
		free(notify_syscalls);
	}
	return ret;
}


int compare_sysno(const void *a, const void *b)
{
	int e1 = *(const int *)a;
	int e2 = *(const int *)b;

	return (e1 > e2) - (e1 < e2);
}

static int generate_notify_profile(char *dir, char *fname,
			struct profile_syscall *list, int len)
{
	int ret = 0, i;
	char tok_path[PATH_MAX] = { 0 };
	char rules_path[PATH_MAX] = { 0 };
	FILE *fp_tok = NULL, *fp_rules = NULL;

	char syscalls[INIT_BUF_LEN] = { 0 };
	int *sysno_list = NULL;

	if (!dir || !fname) {
		fprintf(stderr, "%s: Invalid arguments\n", __func__);
		return -1;
	}
	if (!len || !list) return 0;

	snprintf(tok_path, PATH_MAX, "%s/%s.tok", dir, fname);
	snprintf(rules_path, PATH_MAX, "%s/../audit.rules", dir);

	fp_tok = fopen(tok_path, "w");
	if (!fp_tok) {
		fprintf(stderr, "%s: Failed to open %s\n", __func__, tok_path);
		ret = -1;
		goto out;	
	}

	fp_rules = fopen(rules_path, "a");
	if (!fp_rules) {
		fprintf(stderr, "%s: Failed to open %s\n", __func__, rules_path);
		ret = -1;
		goto out;	
	}

	sysno_list = calloc(len, sizeof(int));
	if (!sysno_list) {
		fprintf(stderr, "%s: Failed to allocate memory\n", __func__);
		ret = -1;
		goto out;
	}

	// output token and syscall list after dedup
	for (i = 0; i < len; i++) {
		struct profile_syscall *cur_profile = &list[i];
		int sysno = cur_profile->sysno;

		sysno_list[i] = sysno;

		// write token to the file
		fprintf(fp_tok, "%s\n", cur_profile->token);
	}

	// sort sysno_list and dedup
	qsort(sysno_list, len, sizeof(int), compare_sysno);

	int unique_num = 1, rules_len = 0;
	for (i = 1; i < len; i++) {
		if (sysno_list[unique_num-1] != sysno_list[i]) {
			sysno_list[unique_num++] = sysno_list[i];
		}
	}

	/* audit rules are loaded by script that executes application workload */
	for (i = 0; i < unique_num; i++) {
		int sysno = sysno_list[i];
		const char *sysname = get_sysname(sysno);
		if (!sysname) {
			fprintf(stderr, "%s: Invalid syscall number %d\n", __func__, sysno);
			ret = -1;
			goto out;
		}

		/* FIXME: don't include sendto() or recvfrom() in audit rules for now;
		audit does not emit SOCKADDR for them */
		if (!strcmp(sysname, "sendto") || !strcmp(sysname, "recvfrom")) continue;

		snprintf(syscalls+rules_len, sizeof(syscalls)-strlen(syscalls), "%s", sysname);
		rules_len += strlen(sysname);
		if (i != (unique_num - 1)) {
			syscalls[rules_len++] = ',';
		}
	}
	fprintf(fp_rules, "-a always,exit -S %s -F exe=%s -F uid!=0 -F euid!=0\n", syscalls, exe_args[0]);

out:
	if (fp_tok) fclose(fp_tok);
	if (fp_rules) fclose(fp_rules);
	free(sysno_list);
	return ret;
}

static inline void usage(char *exe)
{
	fprintf(stderr, "%s -i <profile_script> -o <output_dir>\n", exe);
}

static inline void free_exearg()
{
	int i;
	for (i = 0; i < num_exeargs; i++)
		free(exe_args[i]);
	free(exe_args);
}


/*
	NOTE: need strace to run with -ff then merge, because threads run in parallel
	cause <unfinished ...> strace lines. Add difficulty to parsing.
*/
int main(int argc, char **argv)
{
	int len = 0, ret = 0;
	struct profile_syscall *profile = NULL;
	struct profile_syscall *notify_profile = NULL;
	int profile_len = 0, notify_len = 0;

	struct profile_syscall *strace_list = NULL;
	int opt = 0;
	char *script_path = NULL, *profile_path = NULL;

	/* check options */
	while ((opt = getopt(argc, argv, "i:o:h")) != -1) {
		switch (opt) {
			case 'i':
				script_path = optarg;
				break;
			case 'o':
				profile_path = optarg;
				break;
			case 'h':
				usage(argv[0]);
				goto out;
			default:
				fprintf(stderr, "Invalid argument: %c\n", optopt);
				usage(argv[0]);
				goto out;
		}
	}

	if (!script_path) {
		fprintf(stderr, "Specify script path for profiling\n");
		usage(argv[0]);
		goto out;
	} else {
		FILE *script_stream = NULL;
		char cmd_buf[INIT_BUF_LEN + PATH_MAX] = { 0 };

		/* if profile path is not specified, use default dir */
		if (!profile_path) {
			profile_path = OUTPUT_DIR;
		}

		char script[PATH_MAX] = { 0 };
		snprintf(script, PATH_MAX, "./%s %s", script_path, profile_path);

		/* verify the script and execute */
		script_stream = popen(script, "re");
		if (!script_stream) {
			perror("popen failed:");
			ret = -1;
			goto out;
		}
	
		/* get binary path and its arguments  */
		while (fgets(cmd_buf, INIT_BUF_LEN, script_stream)) {
			if (!num_exeargs) {
				int i = 0;
				char tmp_buf[INIT_BUF_LEN+1] = { 0 };

				// spaces between Tracee: and value are consumed
				ret = sscanf(cmd_buf, "Tracee: %" STRINGIZE(INIT_BUF_LEN) "[^\r\n]", tmp_buf);
				if (ret <= 0)
					continue;
	
				num_exeargs++; // exe path
	
				// remove trailing whitespaces
				char *st = tmp_buf;
				char *end = tmp_buf + strlen(tmp_buf) - 1;
				while (isspace(*end) && (end >= tmp_buf)) { *end-- = '\0'; }
	
				/* extract exe name and args */
				while (*st != '\0') {
					if (isspace(*st)) {
						num_exeargs++;
						while (isspace(*st)) {
							*st++ = '\0';
						}
					} else {
						st++;
					}
				}
	
				exe_args = calloc(num_exeargs, sizeof(char *));
				if (!exe_args) {
					perror("Failed to allocate mem:");
					ret = -1;
					goto out;
				}
	
				st = tmp_buf;
				for (i = 0; i < num_exeargs; i++) {
					while (*st == '\0') st++;

					/* resolve to absolute path if needed */
					if (!i && st[0] != '/') {
						char tmp[PATH_MAX] = { 0 };

						if (resolve_abs_path(st, (char *)tmp)) {
							fprintf(stderr, "Failed to find the binary: %s\n", st);
							ret = -1;
							goto out;
						}
						exe_args[i] = strdup(tmp);
					}
					else {
						exe_args[i] = strdup(st);
					}
					st += strlen(st);
				}

			}

			break;
		}
	
		/* waits for the process to terminate & return the status */
		ret = pclose(script_stream);
		if (ret == -1) {
			fprintf(stderr, "Failed to close script stream: %s\n", strerror(errno));
			goto out;
		}
	
		if (!exe_args) {
			fprintf(stderr, "Not able to acquire tracee path;\n"
					"Wrong script format: %s\n", script_path);
			ret = -1;
			goto out;
		}
	}

	char tracee_name[PATH_MAX] = { 0 };
	char tracee_output[PATH_MAX] = { 0 };
	char json_path[PATH_MAX] = { 0 };

	extract_app_name(exe_args[0], tracee_name);

	// path to the tracee's profile directory
	snprintf(tracee_output, PATH_MAX, "%s/%s", profile_path, tracee_name);

	/* initialize dynamic files list */
	ret = init_dyn_path_list(NULL);
	if (ret) {
		fprintf(stderr, "Failed to init dyn path list\n");
		goto out;
	}

	/* extract strace */
	ret = output_syscall_list(tracee_output, &len, &strace_list);
	if (ret) {
		fprintf(stderr, "Failed to parse strace in dir: %s\n", tracee_output);
		goto out;
	}

	/*
		dedup:
			NOTIFY group is extracted to a separate list.
	 */
	ret = filter_profile_list(strace_list, len,
			&profile, &profile_len,
			&notify_profile, &notify_len);
	if (ret) {
		fprintf(stderr, "Failed to filter profile list\n");
		goto out;
	}

	/* JSON profile for runtime.
		One entry for each element in the NOTIFY group */
	snprintf(json_path, PATH_MAX, "%s/%s.json", tracee_output, tracee_name);

	ret = generate_json_profile(exe_args[0], json_path, "ERRNO",
								profile, profile_len);
	if (ret) {
		fprintf(stderr, "Failed to generate JSON profile\n");
		goto out;
	}

	/*
		auditctl -R requires the rule file owned by root and not readable by others
	*/
	ret = generate_notify_profile(tracee_output, tracee_name, notify_profile, notify_len);
	if (ret) {
		fprintf(stderr, "Failed to generate notify profile\n");
		goto out;
	}

out:
	finalize_dyn_path_list();
	free_profile(len, strace_list); // overall merged list 
	free(profile);
	free(notify_profile);

	free_exearg();

	return ret;
}
