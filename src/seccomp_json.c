#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <seccomp.h>
#include <sys/stat.h>
#include <json-c/json.h>
#include <linux/limits.h>

#include "rasmo_sysname.h"
#include "seccomp_util.h"
#include "seccomp_common.h"

#if defined(__aarch64__)
#define SECCOMP_ARCH "SCMP_ARCH_AARCH64"
#elif defined(__amd64__) || defined(__x86_64__)
#define SECCOMP_ARCH "SCMP_ARCH_X86_64"
#else
#define SECCOMP_ARCH
#endif

struct dictionary action_dict[] = {
	{ SCMP_ACT_ALLOW, "ALLOW" },
#ifdef SECCOMP_USER_NOTIF_FLAG_CONTINUE
	{ SCMP_ACT_NOTIFY, "NOTIFY" },
#endif
//	{ SCMP_ACT_LOG, "SCMP_ACT_LOG" },
//	{ SCMP_ACT_KILL, "SCMP_ACT_KILL" },
//	{ SCMP_ACT_KILL_PROCESS, "SCMP_ACT_KILL_PROCESS" },
	{ SCMP_ACT_ERRNO(EPERM), "ERRNO" },
	{ 0 }
};

struct dictionary op_dict[] = {
	{ SCMP_CMP_EQ, "SCMP_CMP_EQ" },
	{ SCMP_CMP_NE, "SCMP_CMP_NE" },
	{ SCMP_CMP_LT, "SCMP_CMP_LT" },
	{ SCMP_CMP_LE, "SCMP_CMP_LE" },
	{ SCMP_CMP_GE, "SCMP_CMP_GE" },
	{ SCMP_CMP_GT, "SCMP_CMP_GT" },
	{ SCMP_CMP_MASKED_EQ, "SCMP_CMP_MASKED_EQ" }, // need valueTwo field
	{ 0 }
};

int generate_json_profile(char *exe_path, char *output_path,
						char *default_action, void *set, int set_size)
{
	int ret = 0, i;
	json_object *root_object = NULL;
	
	int len = strlen(output_path);
	if (len >= PATH_MAX) {
		fprintf(stderr, "Invalid file name\n");
		ret = -1;
		goto out;
	}

	struct profile_syscall *profile_list = (struct profile_syscall *)set;

 	root_object = json_object_new_object();

	json_object *exe_object = json_object_new_string(exe_path);
	json_object_object_add(root_object, "exe", exe_object);

	json_object *action_object = json_object_new_string(default_action);
	json_object_object_add(root_object, "defaultAction", action_object);

	// encode arch map, AARCH64 only for now
	json_object *arch_object = json_object_new_string(SECCOMP_ARCH);
	json_object_object_add(root_object, "arch", arch_object);

	json_object *num_object = json_object_new_int(set_size);
	json_object_object_add(root_object, "#rules", num_object);

	// encode system calls
	json_object *rules_object = json_object_new_array();

	// encode profiled syscalls
	for (i = 0; i < set_size; i++) {
		struct profile_syscall *cur_profile = &profile_list[i];
		int sysno = cur_profile->sysno;
		const char *name = get_sysname(sysno);
		if (!name) {
			fprintf(stderr, "Invalid syscall number\n");
			ret = -1;
			goto out;
		}

		uint32_t action = cur_profile->action;
#ifdef SECCOMP_USER_NOTIF_FLAG_CONTINUE
		const char *action_str = (action == ALLOW)? "ALLOW" : "NOTIFY";
#else
		const char *action_str = "ALLOW";
#endif
		int num_args = cur_profile->num_args;

		json_object *sysc_object = json_object_new_object();
		json_object *sysc_name = json_object_new_string(name);
		json_object *sysc_action = json_object_new_string(action_str);

		json_object *sysc_no = json_object_new_int(sysno);
		json_object *sysc_num_args = json_object_new_int(num_args);

		json_object_object_add(sysc_object, "name", sysc_name);
		json_object_object_add(sysc_object, "number", sysc_no);
		json_object_object_add(sysc_object, "action", sysc_action);
		json_object_object_add(sysc_object, "#args", sysc_num_args);

		/* add arguments */
		struct syscall_arg *args = cur_profile->args;

		// if NOTIFY: delegate to the tokens, args not recorded in JSON
		if (args && strcmp(action_str, "NOTIFY")) {
			int j;
			json_object *sysc_args = json_object_new_array();

			for (j = 0; j < num_args; j++) {
				struct syscall_arg *cur_arg = &args[j];
				int idx = cur_arg->idx;
				int op = cur_arg->op;
				const char *op_str = val_to_str(op, op_dict);
				uint64_t value = cur_arg->value;

				json_object *arg_obj = json_object_new_object();
				json_object *idx_obj = json_object_new_int(idx);
				json_object *op_obj = json_object_new_string(op_str);
				json_object *value_obj = json_object_new_uint64(value);

				json_object_object_add(arg_obj, "idx", idx_obj);
				json_object_object_add(arg_obj, "op", op_obj);
				json_object_object_add(arg_obj, "value", value_obj);

				/* SCMP_CMP_MASKED_EQ is ignored for now */
				json_object_array_add(sysc_args, arg_obj);
			}
			json_object_object_add(sysc_object, "args", sysc_args);
		}

		json_object_array_add(rules_object, sysc_object);
	}
	json_object_object_add(root_object, "rules", rules_object);

	/* this call will open and truncate the file if it already exists and
		create if not */
	json_object_to_file_ext(output_path, root_object, JSON_C_TO_STRING_PRETTY);

	ret = 0;

out:
	json_object_put(root_object);
	return ret;
}

int load_json_profile(char *fpath, uint32_t *def_action, void **list, int *list_len)
{
	int ret = 0, num_calls = 0;
	struct profile_syscall *profile_list = NULL;

	json_object *profile_obj = NULL;
	uint32_t default_action = 0;

	/* get object from file */
	profile_obj = json_object_from_file(fpath);
	if (!profile_obj) {
		fprintf(stderr, "Failed to get object from %s\n", fpath);
		ret = -1;
		goto out;
	}

	/* get action */
	char *def_action_key = "defaultAction";
	json_object *def_action_obj = NULL;
	ret = json_object_object_get_ex(profile_obj, def_action_key, &def_action_obj);
	if (!ret) {
		fprintf(stderr, "Key does not exist: %s\n", def_action_key);
		ret = -1;
		goto out;
	}

	const char *def_action_str = json_object_get_string(def_action_obj);
	ret = str_to_val(def_action_str, action_dict, &default_action);
	if (ret) {
		fprintf(stderr, "Unrecognized seccomp action: %s\n", def_action_str);
		ret = -1;
		goto out;
	}

	/* get num syscalls */
	char *num_syscall_key = "#rules";
	json_object *num_syscall_obj = NULL;
	ret = json_object_object_get_ex(profile_obj, num_syscall_key, &num_syscall_obj);
	if (!ret) {
		fprintf(stderr, "Key does not exist: %s\n", num_syscall_key);
		ret = -1;
		goto out;
	}
	num_calls = json_object_get_int(num_syscall_obj);

	/* get syscall array object */
	char *array_key = "rules";
	json_object *array_obj = NULL;
	ret = json_object_object_get_ex(profile_obj, array_key, &array_obj);
	if (!ret) {
		fprintf(stderr, "Key does not exist: %s\n", array_key);
		ret = -1;
		goto out;
	}

	/* fill in syscall profile */
	profile_list = calloc(num_calls, sizeof(struct profile_syscall));
	if (!profile_list) {
		perror("Failed to alloc memory: ");
		ret = -1;
		goto out;
	}

	int i;
	for (i = 0; i < num_calls; i++) {
		struct profile_syscall *cur_profile = &profile_list[i];

		json_object *call_obj = json_object_array_get_idx(array_obj, i);
		if (!call_obj) {
			fprintf(stderr, "Failed to extract idx %d from syscall array\n", i);
			ret = -1;
			goto out;
		}

		json_object *sysno_obj = NULL;
		ret = json_object_object_get_ex(call_obj, "number", &sysno_obj);
		if (!ret) {
			fprintf(stderr, "Failed to extract sysno object\n");
			ret = -1;
			goto out;
		}
		int sysno = json_object_get_int(sysno_obj);
		
		json_object *action_obj = NULL;
		ret = json_object_object_get_ex(call_obj, "action", &action_obj);
		if (!ret) {
			fprintf(stderr, "Failed to extract action object\n");
			ret = -1;
			goto out;
		}
		const char *call_action_str = json_object_get_string(action_obj);
		uint32_t call_action = 0;

		ret = str_to_val(call_action_str, action_dict, &call_action);
		if (ret) {
			fprintf(stderr, "Unrecognized seccomp action: %s\n", def_action_str);
			ret = -1;
			goto out;
		}

		json_object *num_args_obj = NULL;
		ret = json_object_object_get_ex(call_obj, "#args", &num_args_obj);
		if (!ret) {
			fprintf(stderr, "Failed to extract #args object\n");
			ret = -1;
			goto out;
		}
		int num_args = json_object_get_int(num_args_obj);

		/* extract each argument */
		struct syscall_arg *args = NULL;
		if (num_args > 0 && call_action ==  SCMP_ACT_ALLOW) {
			int j;

			args = calloc(num_args, sizeof(struct syscall_arg));
			if (!args) {
				perror("Failed to alloc memory for args:");
				ret = -1;
				goto out;
			}

			json_object *args_obj = NULL;
			ret = json_object_object_get_ex(call_obj, "args", &args_obj);
			if (!ret) {
				fprintf(stderr, "Failed to extract args object\n");
				ret = -1;
				goto out;
			}

			for (j = 0; j < num_args; j++) {
				struct syscall_arg *cur_arg = &args[j];

				json_object *arg_obj = json_object_array_get_idx(args_obj, j);
				if (!arg_obj) {
					fprintf(stderr, "Failed to extract args[%d]\n", j);
					ret = -1;
					goto out;
				}
				/* load idx */
				json_object *idx_obj = NULL;
				ret = json_object_object_get_ex(arg_obj, "idx", &idx_obj);
				if (!ret) {
					fprintf(stderr, "Failed to extract idx object\n");
					ret = -1;
					goto out;
				}
				int idx = json_object_get_int(idx_obj);

				/* load op */
				json_object *op_obj = NULL;
				ret = json_object_object_get_ex(arg_obj, "op", &op_obj);
				if (!ret) {
					fprintf(stderr, "Failed to extract op object\n");
					ret = -1;
					goto out;
				}
				const char *op_str = json_object_get_string(op_obj);
				int op = 0;

				ret = str_to_val(op_str, op_dict, &op);
				if (ret) {
					fprintf(stderr, "Unrecognized op: %s\n", op_str);
					ret = -1;
					goto out;
				}

				/* load value */
				json_object *value_obj = NULL;
				ret = json_object_object_get_ex(arg_obj, "value", &value_obj);
				if (!ret) {
					fprintf(stderr, "Failed to extract value object\n");
					ret = -1;
					goto out;
				}
				uint64_t value = json_object_get_uint64(value_obj);

				cur_arg->idx = idx;
				cur_arg->op = op;
				cur_arg->value = value;
				cur_arg->type = VAL_ARG;

				/* value_two and SCMP_CMP_MASKED_EQ skip for now */
			}
		}

		cur_profile->sysno = sysno;
		cur_profile->action = call_action;
		cur_profile->num_args = num_args;
		cur_profile->args = args;
	}

	*def_action = default_action;
	*list = profile_list;
	*list_len = num_calls;

	ret = 0;

out:
	// free memory if error occured
	if (ret) free(profile_list);

	json_object_put(profile_obj);
	return ret;
}
