#ifndef _COMMON_H_
#define _COMMON_H_

#define ALLOW 1
#define NOTIFY 2
#define OUTPUT_DIR "output"

enum arg_type {
	VAL_ARG,
	PTR_ARG
};

struct syscall_arg {
	int idx;
	enum arg_type type;
	union {
		uint64_t value;
		char *string; // need to be free'd
	};
	int op;			// enum scmp_compare, for non-notify I guess? (-1 otherwise)
	/* 
		uint64_t value_two; 	// used for SCMP_CMP_MASKED_EQ only; not used yet
	*/
};

struct file_info {
	int file_exist;
	ino_t inode;
	int dev_major;
	int dev_minor;
	mode_t mode;
	char path[PATH_MAX]; // without quote marks
};

/* 
	if action is SCMP_ACT_ALLOW:
	* default rule with no args to be checked (sc.1: parse func NULL)
		-> args empty
	* only args with no pointer dereference needed (sc.2: with parse func)
		-> generate type VAL_ARG, arg type int

   if action is SCMP_ACT_NOTIFY:
	* args: string (e.g., file path) or struct (e.g., sockaddr) (sc.3: with parse func)
		-> generate type PTR_ARG
		--> output arg as strings if path name
		--> socket output SOCKADDR hex decimal
		-> generat bloom filter
*/

struct profile_syscall {
	int sysno;
	uint32_t action;		// seccomp action for the call
	int num_args;			// number of args to be profiled
	struct syscall_arg *args; // allowed set of args (need to be free'd if not NULL)
	char *token; // token encoding (need to be free'd if not NULL)
};

#endif
