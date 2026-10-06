#ifndef _SYSNAME_H_
#define _SYSNAME_H_

#include <linux/types.h>
#include <sys/syscall.h>

typedef int (*profile_func_ptr)(char *, void *);
typedef int (*rt_func_ptr)(int, __u64 *, char *);
typedef int (*sysftr_func_ptr)(char *, char *);

struct syscall_ops {
	profile_func_ptr profile;
	rt_func_ptr rt;
	sysftr_func_ptr sysftr;
};

struct syscall_table {
	const char *name;
	unsigned int sysno;
	struct syscall_ops parse_func;	
};

#define SYSCALL_MAX	451
#define SYSNO(name) __NR_##name
#define PARSER(name) { .profile = name##_parse,\
				 .rt = name##_rt_parse, \
				 .sysftr = name##_sysftr_parse }

// declared weak for both profiler and runtime loader
#define DECLARE_PARSER(name) \
	__attribute__((weak)) int name##_parse(char *, void *);\
	__attribute__((weak)) int name##_rt_parse(int, __u64 *, char *);\
	__attribute__((weak)) int name##_sysftr_parse(char *, char *);
	

#define get_parse_func(_sysno, which) ({\
	which##_func_ptr ptr = NULL;\
	if (_sysno >= 0 && _sysno < SYSCALL_MAX) {\
		ptr = systable[_sysno].parse_func.which;\
	}\
	ptr;\
})

#define get_sysname(_sysno) ({\
	const char *name = NULL;\
	if (_sysno >= 0 && _sysno < SYSCALL_MAX) {\
		name = systable[_sysno].name;\
	}\
	name;\
})

__attribute__((weak)) int default_parse(char *, void *);

/* SCMP_ACT_NOTIFY: filename */
DECLARE_PARSER(execve)
DECLARE_PARSER(openat)
DECLARE_PARSER(faccessat)
DECLARE_PARSER(statfs)
DECLARE_PARSER(newfstatat)
DECLARE_PARSER(readlinkat)

/* SCMP_ACT_NOTIFY: sockaddr */
DECLARE_PARSER(bind)
DECLARE_PARSER(connect)
DECLARE_PARSER(recvmsg)
DECLARE_PARSER(sendto)
DECLARE_PARSER(sendmmsg)

/* section: SCMP_ACT_ALLOW with args */
DECLARE_PARSER(socket)
DECLARE_PARSER(ioctl)
DECLARE_PARSER(clone)
DECLARE_PARSER(mmap)
DECLARE_PARSER(futex)
DECLARE_PARSER(recvfrom)

static struct syscall_table systable[SYSCALL_MAX] = {
	{ .name = "io_setup", .sysno = 0, { 0 } } , 	/* 0 */
	{ .name = "io_destroy", .sysno = 1, { 0 } } , 	/* 1 */
	{ .name = "io_submit", .sysno = 2, { 0 } } , 	/* 2 */
	{ .name = "io_cancel", .sysno = 3, { 0 } } , 	/* 3 */
	{ .name = "io_getevents", .sysno = 4, { 0 } } , 	/* 4 */
	{ .name = "setxattr", .sysno = 5, { 0 } } , 	/* 5 */
	{ .name = "lsetxattr", .sysno = 6, { 0 } } , 	/* 6 */
	{ .name = "fsetxattr", .sysno = 7, { 0 } } , 	/* 7 */
	{ .name = "getxattr", .sysno = 8, { 0 } } , 	/* 8 */
	{ .name = "lgetxattr", .sysno = 9, { 0 } } , 	/* 9 */
	{ .name = "fgetxattr", .sysno = 10, { 0 } } , 	/* 10 */
	{ .name = "listxattr", .sysno = 11, { 0 } } , 	/* 11 */
	{ .name = "llistxattr", .sysno = 12, { 0 } } , 	/* 12 */
	{ .name = "flistxattr", .sysno = 13, { 0 } } , 	/* 13 */
	{ .name = "removexattr", .sysno = 14, { 0 } } , 	/* 14 */
	{ .name = "lremovexattr", .sysno = 15, { 0 } } , 	/* 15 */
	{ .name = "fremovexattr", .sysno = 16, { 0 } } , 	/* 16 */
	{ .name = "getcwd", .sysno = 17, { 0 } } , 	/* 17 */
	{ .name = "lookup_dcookie", .sysno = 18, { 0 } } , 	/* 18 */
	{ .name = "eventfd2", .sysno = 19, { 0 } } , 	/* 19 */
	{ .name = "epoll_create1", .sysno = 20, { 0 } } , 	/* 20 */
	{ .name = "epoll_ctl", .sysno = 21, { 0 } } , 	/* 21 */
	{ .name = "epoll_pwait", .sysno = 22, { 0 } } , 	/* 22 */
	{ .name = "dup", .sysno = 23, { 0 } } , 	/* 23 */
	{ .name = "dup3", .sysno = 24, { 0 } } , 	/* 24 */
	{ .name = "fcntl", .sysno = 25, { 0 } } , 	/* 25 */
	{ .name = "inotify_init1", .sysno = 26, { 0 } } , 	/* 26 */
	{ .name = "inotify_add_watch", .sysno = 27, { 0 } } , 	/* 27 */
	{ .name = "inotify_rm_watch", .sysno = 28, { 0 } } , 	/* 28 */
	{ .name = "ioctl", .sysno = 29, PARSER(ioctl) } , 	/* 29 */
//	{ .name = "ioctl", .sysno = 29, { 0 } } , 	/* DEBUG */
	{ .name = "ioprio_set", .sysno = 30, { 0 } } , 	/* 30 */
	{ .name = "ioprio_get", .sysno = 31, { 0 } } , 	/* 31 */
	{ .name = "flock", .sysno = 32, { 0 } } , 	/* 32 */
	{ .name = "mknodat", .sysno = 33, { 0 } } , 	/* 33 */
	{ .name = "mkdirat", .sysno = 34, { 0 } } , 	/* 34 */
	{ .name = "unlinkat", .sysno = 35, { 0 } } , 	/* 35 */
	{ .name = "symlinkat", .sysno = 36, { 0 } } , 	/* 36 */
	{ .name = "linkat", .sysno = 37, { 0 } } , 	/* 37 */
	{ .name = "renameat", .sysno = 38, { 0 } } , 	/* 38 */
	{ .name = "umount2", .sysno = 39, { 0 } } , 	/* 39 */
	{ .name = "mount", .sysno = 40, { 0 } } , 	/* 40 */
	{ .name = "pivot_root", .sysno = 41, { 0 } } , 	/* 41 */
	{ .name = "nfsservctl", .sysno = 42, { 0 } } , 	/* 42 */
	{ .name = "statfs", .sysno = 43, PARSER(statfs) } , 	/* 43 */
	{ .name = "fstatfs", .sysno = 44, { 0 } } , 	/* 44 */
	{ .name = "truncate", .sysno = 45, { 0 } } , 	/* 45 */
	{ .name = "ftruncate", .sysno = 46, { 0 } } , 	/* 46 */
	{ .name = "fallocate", .sysno = 47, { 0 } } , 	/* 47 */
	{ .name = "faccessat", .sysno = 48, PARSER(faccessat) } , 	/* 48 */
	{ .name = "chdir", .sysno = 49, { 0 } } , 	/* 49 */
	{ .name = "fchdir", .sysno = 50, { 0 } } , 	/* 50 */
	{ .name = "chroot", .sysno = 51, { 0 } } , 	/* 51 */
	{ .name = "fchmod", .sysno = 52, { 0 } } , 	/* 52 */
	{ .name = "fchmodat", .sysno = 53, { 0 } } , 	/* 53 */
	{ .name = "fchownat", .sysno = 54, { 0 } } , 	/* 54 */
	{ .name = "fchown", .sysno = 55, { 0 } } , 	/* 55 */
	{ .name = "openat", .sysno = 56, PARSER(openat) } , 	/* 56 */
	{ .name = "close", .sysno = 57, { 0 } } , 	/* 57 */
	{ .name = "vhangup", .sysno = 58, { 0 } } , 	/* 58 */
	{ .name = "pipe2", .sysno = 59, { 0 } } , 	/* 59 */
	{ .name = "quotactl", .sysno = 60, { 0 } } , 	/* 60 */
	{ .name = "getdents", .sysno = 61, { 0 } } , 	/* 61 */
	{ .name = "lseek", .sysno = 62, { 0 } } , 	/* 62 */
	{ .name = "read", .sysno = 63, { 0 } } , 	/* 63 */
	{ .name = "write", .sysno = 64, { 0 } } , 	/* 64 */
	{ .name = "readv", .sysno = 65, { 0 } } , 	/* 65 */
	{ .name = "writev", .sysno = 66, { 0 } } , 	/* 66 */
	{ .name = "pread", .sysno = 67, { 0 } } , 	/* 67 */
	{ .name = "pwrite", .sysno = 68, { 0 } } , 	/* 68 */
	{ .name = "preadv", .sysno = 69, { 0 } } , 	/* 69 */
	{ .name = "pwritev", .sysno = 70, { 0 } } , 	/* 70 */
	{ .name = "sendfile", .sysno = 71, { 0 } } , 	/* 71 */
	{ .name = "pselect6", .sysno = 72, { 0 } } , 	/* 72 */
	{ .name = "ppoll", .sysno = 73, { 0 } } , 	/* 73 */
	{ .name = "signalfd4", .sysno = 74, { 0 } } , 	/* 74 */
	{ .name = "vmsplice", .sysno = 75, { 0 } } , 	/* 75 */
	{ .name = "splice", .sysno = 76, { 0 } } , 	/* 76 */
	{ .name = "tee", .sysno = 77, { 0 } } , 	/* 77 */
	{ .name = "readlinkat", .sysno = 78, PARSER(readlinkat) } , 	/* 78 */
	{ .name = "newfstatat", .sysno = 79, PARSER(newfstatat) } , 	/* 79 */
	{ .name = "newfstat", .sysno = 80, { 0 } } , 	/* 80 */
	{ .name = "sync", .sysno = 81, { 0 } } , 	/* 81 */
	{ .name = "fsync", .sysno = 82, { 0 } } , 	/* 82 */
	{ .name = "fdatasync", .sysno = 83, { 0 } } , 	/* 83 */
	{ .name = "sync_file_range", .sysno = 84, { 0 } } , 	/* 84 */
	{ .name = "timerfd_create", .sysno = 85, { 0 } } , 	/* 85 */
	{ .name = "timerfd_settime", .sysno = 86, { 0 } } , 	/* 86 */
	{ .name = "timerfd_gettime", .sysno = 87, { 0 } } , 	/* 87 */
	{ .name = "utimensat", .sysno = 88, { 0 } } , 	/* 88 */
	{ .name = "acct", .sysno = 89, { 0 } } , 	/* 89 */
	{ .name = "capget", .sysno = 90, { 0 } } , 	/* 90 */
	{ .name = "capset", .sysno = 91, { 0 } } , 	/* 91 */
	{ .name = "personality", .sysno = 92, { 0 } } , 	/* 92 */
	{ .name = "exit", .sysno = 93, { 0 } } , 	/* 93 */
	{ .name = "exit_group", .sysno = 94, { 0 } } , 	/* 94 */
	{ .name = "waitid", .sysno = 95, { 0 } } , 	/* 95 */
	{ .name = "set_tid_address", .sysno = 96, { 0 } } , 	/* 96 */
	{ .name = "unshare", .sysno = 97, { 0 } } , 	/* 97 */
	{ .name = "futex", .sysno = 98, PARSER(futex) } , 	/* 98 */
//	{ .name = "futex", .sysno = 98, { 0 } } , 	/* DEBUG */
	{ .name = "set_robust_list", .sysno = 99, { 0 } } , 	/* 99 */
	{ .name = "get_robust_list", .sysno = 100, { 0 } } , 	/* 100 */
	{ .name = "nanosleep", .sysno = 101, { 0 } } , 	/* 101 */
	{ .name = "getitimer", .sysno = 102, { 0 } } , 	/* 102 */
	{ .name = "setitimer", .sysno = 103, { 0 } } , 	/* 103 */
	{ .name = "kexec_load", .sysno = 104, { 0 } } , 	/* 104 */
	{ .name = "init_module", .sysno = 105, { 0 } } , 	/* 105 */
	{ .name = "delete_module", .sysno = 106, { 0 } } , 	/* 106 */
	{ .name = "timer_create", .sysno = 107, { 0 } } , 	/* 107 */
	{ .name = "timer_gettime", .sysno = 108, { 0 } } , 	/* 108 */
	{ .name = "timer_getoverrun", .sysno = 109, { 0 } } , 	/* 109 */
	{ .name = "timer_settime", .sysno = 110, { 0 } } , 	/* 110 */
	{ .name = "timer_delete", .sysno = 111, { 0 } } , 	/* 111 */
	{ .name = "clock_settime", .sysno = 112, { 0 } } , 	/* 112 */
	{ .name = "clock_gettime", .sysno = 113, { 0 } } , 	/* 113 */
	{ .name = "clock_getres", .sysno = 114, { 0 } } , 	/* 114 */
	{ .name = "clock_nanosleep", .sysno = 115, { 0 } } , 	/* 115 */
	{ .name = "syslog", .sysno = 116, { 0 } } , 	/* 116 */
	{ .name = "ptrace", .sysno = 117, { 0 } } , 	/* 117 */
	{ .name = "sched_setparam", .sysno = 118, { 0 } } , 	/* 118 */
	{ .name = "sched_setscheduler", .sysno = 119, { 0 } } , 	/* 119 */
	{ .name = "sched_getscheduler", .sysno = 120, { 0 } } , 	/* 120 */
	{ .name = "sched_getparam", .sysno = 121, { 0 } } , 	/* 121 */
	{ .name = "sched_setaffinity", .sysno = 122, { 0 } } , 	/* 122 */
	{ .name = "sched_getaffinity", .sysno = 123, { 0 } } , 	/* 123 */
	{ .name = "sched_yield", .sysno = 124, { 0 } } , 	/* 124 */
	{ .name = "sched_get_priority_max", .sysno = 125, { 0 } } , 	/* 125 */
	{ .name = "sched_get_priority_min", .sysno = 126, { 0 } } , 	/* 126 */
	{ .name = "sched_rr_get_interval", .sysno = 127, { 0 } } , 	/* 127 */
	{ .name = "restart_syscall", .sysno = 128, { 0 } } , 	/* 128 */
	{ .name = "kill", .sysno = 129, { 0 } } , 	/* 129 */
	{ .name = "tkill", .sysno = 130, { 0 } } , 	/* 130 */
	{ .name = "tgkill", .sysno = 131, { 0 } } , 	/* 131 */
	{ .name = "sigaltstack", .sysno = 132, { 0 } } , 	/* 132 */
	{ .name = "rt_sigsuspend", .sysno = 133, { 0 } } , 	/* 133 */
	{ .name = "rt_sigaction", .sysno = 134, { 0 } } , 	/* 134 */
	{ .name = "rt_sigprocmask", .sysno = 135, { 0 } } , 	/* 135 */
	{ .name = "rt_sigpending", .sysno = 136, { 0 } } , 	/* 136 */
	{ .name = "rt_sigtimedwait", .sysno = 137, { 0 } } , 	/* 137 */
	{ .name = "rt_sigqueueinfo", .sysno = 138, { 0 } } , 	/* 138 */
	{ .name = "rt_sigreturn", .sysno = 139, { 0 } } , 	/* 139 */
	{ .name = "setpriority", .sysno = 140, { 0 } } , 	/* 140 */
	{ .name = "getpriority", .sysno = 141, { 0 } } , 	/* 141 */
	{ .name = "reboot", .sysno = 142, { 0 } } , 	/* 142 */
	{ .name = "setregid", .sysno = 143, { 0 } } , 	/* 143 */
	{ .name = "setgid", .sysno = 144, { 0 } } , 	/* 144 */
	{ .name = "setreuid", .sysno = 145, { 0 } } , 	/* 145 */
	{ .name = "setuid", .sysno = 146, { 0 } } , 	/* 146 */
	{ .name = "setresuid", .sysno = 147, { 0 } } , 	/* 147 */
	{ .name = "getresuid", .sysno = 148, { 0 } } , 	/* 148 */
	{ .name = "setresgid", .sysno = 149, { 0 } } , 	/* 149 */
	{ .name = "getresgid", .sysno = 150, { 0 } } , 	/* 150 */
	{ .name = "setfsuid", .sysno = 151, { 0 } } , 	/* 151 */
	{ .name = "setfsgid", .sysno = 152, { 0 } } , 	/* 152 */
	{ .name = "times", .sysno = 153, { 0 } } , 	/* 153 */
	{ .name = "setpgid", .sysno = 154, { 0 } } , 	/* 154 */
	{ .name = "getpgid", .sysno = 155, { 0 } } , 	/* 155 */
	{ .name = "getsid", .sysno = 156, { 0 } } , 	/* 156 */
	{ .name = "setsid", .sysno = 157, { 0 } } , 	/* 157 */
	{ .name = "getgroups", .sysno = 158, { 0 } } , 	/* 158 */
	{ .name = "setgroups", .sysno = 159, { 0 } } , 	/* 159 */
	{ .name = "uname", .sysno = 160, { 0 } } , 	/* 160 */
	{ .name = "sethostname", .sysno = 161, { 0 } } , 	/* 161 */
	{ .name = "setdomainname", .sysno = 162, { 0 } } , 	/* 162 */
	{ .name = "getrlimit", .sysno = 163, { 0 } } , 	/* 163 */
	{ .name = "setrlimit", .sysno = 164, { 0 } } , 	/* 164 */
	{ .name = "getrusage", .sysno = 165, { 0 } } , 	/* 165 */
	{ .name = "umask", .sysno = 166, { 0 } } , 	/* 166 */
	{ .name = "prctl", .sysno = 167, { 0 } } , 	/* 167 */
	{ .name = "getcpu", .sysno = 168, { 0 } } , 	/* 168 */
	{ .name = "gettimeofday", .sysno = 169, { 0 } } , 	/* 169 */
	{ .name = "settimeofday", .sysno = 170, { 0 } } , 	/* 170 */
	{ .name = "adjtimex", .sysno = 171, { 0 } } , 	/* 171 */
	{ .name = "getpid", .sysno = 172, { 0 } } , 	/* 172 */
	{ .name = "getppid", .sysno = 173, { 0 } } , 	/* 173 */
	{ .name = "getuid", .sysno = 174, { 0 } } , 	/* 174 */
	{ .name = "geteuid", .sysno = 175, { 0 } } , 	/* 175 */
	{ .name = "getgid", .sysno = 176, { 0 } } , 	/* 176 */
	{ .name = "getegid", .sysno = 177, { 0 } } , 	/* 177 */
	{ .name = "gettid", .sysno = 178, { 0 } } , 	/* 178 */
	{ .name = "sysinfo", .sysno = 179, { 0 } } , 	/* 179 */
	{ .name = "mq_open", .sysno = 180, { 0 } } , 	/* 180 */
	{ .name = "mq_unlink", .sysno = 181, { 0 } } , 	/* 181 */
	{ .name = "mq_timedsend", .sysno = 182, { 0 } } , 	/* 182 */
	{ .name = "mq_timedreceive", .sysno = 183, { 0 } } , 	/* 183 */
	{ .name = "mq_notify", .sysno = 184, { 0 } } , 	/* 184 */
	{ .name = "mq_getsetattr", .sysno = 185, { 0 } } , 	/* 185 */
	{ .name = "msgget", .sysno = 186, { 0 } } , 	/* 186 */
	{ .name = "msgctl", .sysno = 187, { 0 } } , 	/* 187 */
	{ .name = "msgrcv", .sysno = 188, { 0 } } , 	/* 188 */
	{ .name = "msgsnd", .sysno = 189, { 0 } } , 	/* 189 */
	{ .name = "semget", .sysno = 190, { 0 } } , 	/* 190 */
	{ .name = "semctl", .sysno = 191, { 0 } } , 	/* 191 */
	{ .name = "semtimedop", .sysno = 192, { 0 } } , 	/* 192 */
	{ .name = "semop", .sysno = 193, { 0 } } , 	/* 193 */
	{ .name = "shmget", .sysno = 194, { 0 } } , 	/* 194 */
	{ .name = "shmctl", .sysno = 195, { 0 } } , 	/* 195 */
	{ .name = "shmat", .sysno = 196, { 0 } } , 	/* 196 */
	{ .name = "shmdt", .sysno = 197, { 0 } } , 	/* 197 */
	{ .name = "socket", .sysno = 198, PARSER(socket) } , 	/* 198 */
	{ .name = "socketpair", .sysno = 199, { 0 } } , 	/* 199 */
	{ .name = "bind", .sysno = 200, PARSER(bind) } , 	/* 200 */
	{ .name = "listen", .sysno = 201, { 0 } } , 	/* 201 */
	{ .name = "accept", .sysno = 202, { 0 } } , 	/* 202 */
	{ .name = "connect", .sysno = 203, PARSER(connect) } , 	/* 203 */
	{ .name = "getsockname", .sysno = 204, { 0 } } , 	/* 204 */
	{ .name = "getpeername", .sysno = 205, { 0 } } , 	/* 205 */
	{ .name = "sendto", .sysno = 206, PARSER(sendto) } , 	/* 206 */
	{ .name = "recvfrom", .sysno = 207, PARSER(recvfrom) } , 	/* 207 */
	{ .name = "setsockopt", .sysno = 208, { 0 } } , 	/* 208 */
	{ .name = "getsockopt", .sysno = 209, { 0 } } , 	/* 209 */
	{ .name = "shutdown", .sysno = 210, { 0 } } , 	/* 210 */
	{ .name = "sendmsg", .sysno = 211, { 0 } } , 	/* 211 */
	{ .name = "recvmsg", .sysno = 212, PARSER(recvmsg) } , 	/* 212 */
	{ .name = "readahead", .sysno = 213, { 0 } } , 	/* 213 */
	{ .name = "brk", .sysno = 214, { 0 } } , 	/* 214 */
	{ .name = "munmap", .sysno = 215, { 0 } } , 	/* 215 */
	{ .name = "mremap", .sysno = 216, { 0 } } , 	/* 216 */
	{ .name = "add_key", .sysno = 217, { 0 } } , 	/* 217 */
	{ .name = "request_key", .sysno = 218, { 0 } } , 	/* 218 */
	{ .name = "keyctl", .sysno = 219, { 0 } } , 	/* 219 */
	{ .name = "clone", .sysno = 220, PARSER(clone) } , 	/* 220 */
	{ .name = "execve", .sysno = 221, PARSER(execve) } , 	/* 221 */
	{ .name = "mmap", .sysno = 222, PARSER(mmap) } , 	/* 222 */
	{ .name = "fadvise64", .sysno = 223, { 0 } } , 	/* 223 */
	{ .name = "swapon", .sysno = 224, { 0 } } , 	/* 224 */
	{ .name = "swapoff", .sysno = 225, { 0 } } , 	/* 225 */
	{ .name = "mprotect", .sysno = 226, { 0 } } , 	/* 226 */
	{ .name = "msync", .sysno = 227, { 0 } } , 	/* 227 */
	{ .name = "mlock", .sysno = 228, { 0 } } , 	/* 228 */
	{ .name = "munlock", .sysno = 229, { 0 } } , 	/* 229 */
	{ .name = "mlockall", .sysno = 230, { 0 } } , 	/* 230 */
	{ .name = "munlockall", .sysno = 231, { 0 } } , 	/* 231 */
	{ .name = "mincore", .sysno = 232, { 0 } } , 	/* 232 */
	{ .name = "madvise", .sysno = 233, { 0 } } , 	/* 233 */
	{ .name = "remap_file_pages", .sysno = 234, { 0 } } , 	/* 234 */
	{ .name = "mbind", .sysno = 235, { 0 } } , 	/* 235 */
	{ .name = "get_mempolicy", .sysno = 236, { 0 } } , 	/* 236 */
	{ .name = "set_mempolicy", .sysno = 237, { 0 } } , 	/* 237 */
	{ .name = "migrate_pages", .sysno = 238, { 0 } } , 	/* 238 */
	{ .name = "move_pages", .sysno = 239, { 0 } } , 	/* 239 */
	{ .name = "rt_tgsigqueueinfo", .sysno = 240, { 0 } } , 	/* 240 */
	{ .name = "perf_event_open", .sysno = 241, { 0 } } , 	/* 241 */
	{ .name = "accept4", .sysno = 242, { 0 } } , 	/* 242 */
	{ .name = "recvmmsg", .sysno = 243, { 0 } } , 	/* 243 */
	{ 0 } , 		/* 244 */
	{ 0 } , 		/* 245 */
	{ 0 } , 		/* 246 */
	{ 0 } , 		/* 247 */
	{ 0 } , 		/* 248 */
	{ 0 } , 		/* 249 */
	{ 0 } , 		/* 250 */
	{ 0 } , 		/* 251 */
	{ 0 } , 		/* 252 */
	{ 0 } , 		/* 253 */
	{ 0 } , 		/* 254 */
	{ 0 } , 		/* 255 */
	{ 0 } , 		/* 256 */
	{ 0 } , 		/* 257 */
	{ 0 } , 		/* 258 */
	{ 0 } , 		/* 259 */
	{ .name = "wait4", .sysno = 260, { 0 } } , 	/* 260 */
	{ .name = "prlimit64", .sysno = 261, { 0 } } , 	/* 261 */
	{ .name = "fanotify_init", .sysno = 262, { 0 } } , 	/* 262 */
	{ .name = "fanotify_mark", .sysno = 263, { 0 } } , 	/* 263 */
	{ .name = "name_to_handle_at", .sysno = 264, { 0 } } , 	/* 264 */
	{ .name = "open_by_handle_at", .sysno = 265, { 0 } } , 	/* 265 */
	{ .name = "clock_adjtime", .sysno = 266, { 0 } } , 	/* 266 */
	{ .name = "syncfs", .sysno = 267, { 0 } } , 	/* 267 */
	{ .name = "setns", .sysno = 268, { 0 } } , 	/* 268 */
	{ .name = "sendmmsg", .sysno = 269, PARSER(sendmmsg) } , 	/* 269 */
	{ .name = "process_vm_readv", .sysno = 270, { 0 } } , 	/* 270 */
	{ .name = "process_vm_writev", .sysno = 271, { 0 } } , 	/* 271 */
	{ .name = "kcmp", .sysno = 272, { 0 } } , 	/* 272 */
	{ .name = "finit_module", .sysno = 273, { 0 } } , 	/* 273 */
	{ .name = "sched_setattr", .sysno = 274, { 0 } } , 	/* 274 */
	{ .name = "sched_getattr", .sysno = 275, { 0 } } , 	/* 275 */
	{ .name = "renameat2", .sysno = 276, { 0 } } , 	/* 276 */
	{ .name = "seccomp", .sysno = 277, { 0 } } , 	/* 277 */
	{ .name = "getrandom", .sysno = 278, { 0 } } , 	/* 278 */
	{ .name = "memfd_create", .sysno = 279, { 0 } } , 	/* 279 */
	{ .name = "bpf", .sysno = 280, { 0 } } , 	/* 280 */
	{ .name = "execveat", .sysno = 281, { 0 } } , 	/* 281 */
	{ .name = "userfaultfd", .sysno = 282, { 0 } } , 	/* 282 */
	{ .name = "membarrier", .sysno = 283, { 0 } } , 	/* 283 */
	{ .name = "mlock2", .sysno = 284, { 0 } } , 	/* 284 */
	{ .name = "copy_file_range", .sysno = 285, { 0 } } , 	/* 285 */
	{ .name = "preadv2", .sysno = 286, { 0 } } , 	/* 286 */
	{ .name = "pwritev2", .sysno = 287, { 0 } } , 	/* 287 */
	{ .name = "pkey_mprotect", .sysno = 288, { 0 } } , 	/* 288 */
	{ .name = "pkey_alloc", .sysno = 289, { 0 } } , 	/* 289 */
	{ .name = "pkey_free", .sysno = 290, { 0 } } , 	/* 290 */
	{ .name = "statx", .sysno = 291, { 0 } } , 	/* 291 */
	{ .name = "io_pgetevents", .sysno = 292, { 0 } } , 	/* 292 */
	{ .name = "rseq", .sysno = 293, { 0 } } , 	/* 293 */
	{ .name = "kexec_file_load", .sysno = 294, { 0 } } , 	/* 294 */
	{ 0 } , 		/* 295 */
	{ 0 } , 		/* 296 */
	{ 0 } , 		/* 297 */
	{ 0 } , 		/* 298 */
	{ 0 } , 		/* 299 */
	{ 0 } , 		/* 300 */
	{ 0 } , 		/* 301 */
	{ 0 } , 		/* 302 */
	{ 0 } , 		/* 303 */
	{ 0 } , 		/* 304 */
	{ 0 } , 		/* 305 */
	{ 0 } , 		/* 306 */
	{ 0 } , 		/* 307 */
	{ 0 } , 		/* 308 */
	{ 0 } , 		/* 309 */
	{ 0 } , 		/* 310 */
	{ 0 } , 		/* 311 */
	{ 0 } , 		/* 312 */
	{ 0 } , 		/* 313 */
	{ 0 } , 		/* 314 */
	{ 0 } , 		/* 315 */
	{ 0 } , 		/* 316 */
	{ 0 } , 		/* 317 */
	{ 0 } , 		/* 318 */
	{ 0 } , 		/* 319 */
	{ 0 } , 		/* 320 */
	{ 0 } , 		/* 321 */
	{ 0 } , 		/* 322 */
	{ 0 } , 		/* 323 */
	{ 0 } , 		/* 324 */
	{ 0 } , 		/* 325 */
	{ 0 } , 		/* 326 */
	{ 0 } , 		/* 327 */
	{ 0 } , 		/* 328 */
	{ 0 } , 		/* 329 */
	{ 0 } , 		/* 330 */
	{ 0 } , 		/* 331 */
	{ 0 } , 		/* 332 */
	{ 0 } , 		/* 333 */
	{ 0 } , 		/* 334 */
	{ 0 } , 		/* 335 */
	{ 0 } , 		/* 336 */
	{ 0 } , 		/* 337 */
	{ 0 } , 		/* 338 */
	{ 0 } , 		/* 339 */
	{ 0 } , 		/* 340 */
	{ 0 } , 		/* 341 */
	{ 0 } , 		/* 342 */
	{ 0 } , 		/* 343 */
	{ 0 } , 		/* 344 */
	{ 0 } , 		/* 345 */
	{ 0 } , 		/* 346 */
	{ 0 } , 		/* 347 */
	{ 0 } , 		/* 348 */
	{ 0 } , 		/* 349 */
	{ 0 } , 		/* 350 */
	{ 0 } , 		/* 351 */
	{ 0 } , 		/* 352 */
	{ 0 } , 		/* 353 */
	{ 0 } , 		/* 354 */
	{ 0 } , 		/* 355 */
	{ 0 } , 		/* 356 */
	{ 0 } , 		/* 357 */
	{ 0 } , 		/* 358 */
	{ 0 } , 		/* 359 */
	{ 0 } , 		/* 360 */
	{ 0 } , 		/* 361 */
	{ 0 } , 		/* 362 */
	{ 0 } , 		/* 363 */
	{ 0 } , 		/* 364 */
	{ 0 } , 		/* 365 */
	{ 0 } , 		/* 366 */
	{ 0 } , 		/* 367 */
	{ 0 } , 		/* 368 */
	{ 0 } , 		/* 369 */
	{ 0 } , 		/* 370 */
	{ 0 } , 		/* 371 */
	{ 0 } , 		/* 372 */
	{ 0 } , 		/* 373 */
	{ 0 } , 		/* 374 */
	{ 0 } , 		/* 375 */
	{ 0 } , 		/* 376 */
	{ 0 } , 		/* 377 */
	{ 0 } , 		/* 378 */
	{ 0 } , 		/* 379 */
	{ 0 } , 		/* 380 */
	{ 0 } , 		/* 381 */
	{ 0 } , 		/* 382 */
	{ 0 } , 		/* 383 */
	{ 0 } , 		/* 384 */
	{ 0 } , 		/* 385 */
	{ 0 } , 		/* 386 */
	{ 0 } , 		/* 387 */
	{ 0 } , 		/* 388 */
	{ 0 } , 		/* 389 */
	{ 0 } , 		/* 390 */
	{ 0 } , 		/* 391 */
	{ 0 } , 		/* 392 */
	{ 0 } , 		/* 393 */
	{ 0 } , 		/* 394 */
	{ 0 } , 		/* 395 */
	{ 0 } , 		/* 396 */
	{ 0 } , 		/* 397 */
	{ 0 } , 		/* 398 */
	{ 0 } , 		/* 399 */
	{ 0 } , 		/* 400 */
	{ 0 } , 		/* 401 */
	{ 0 } , 		/* 402 */
	{ 0 } , 		/* 403 */
	{ 0 } , 		/* 404 */
	{ 0 } , 		/* 405 */
	{ 0 } , 		/* 406 */
	{ 0 } , 		/* 407 */
	{ 0 } , 		/* 408 */
	{ 0 } , 		/* 409 */
	{ 0 } , 		/* 410 */
	{ 0 } , 		/* 411 */
	{ 0 } , 		/* 412 */
	{ 0 } , 		/* 413 */
	{ 0 } , 		/* 414 */
	{ 0 } , 		/* 415 */
	{ 0 } , 		/* 416 */
	{ 0 } , 		/* 417 */
	{ 0 } , 		/* 418 */
	{ 0 } , 		/* 419 */
	{ 0 } , 		/* 420 */
	{ 0 } , 		/* 421 */
	{ 0 } , 		/* 422 */
	{ 0 } , 		/* 423 */
	{ .name = "pidfd_send_signal", .sysno = 424, { 0 } } , 	/* 424 */
	{ .name = "io_uring_setup", .sysno = 425, { 0 } } , 	/* 425 */
	{ .name = "io_uring_enter", .sysno = 426, { 0 } } , 	/* 426 */
	{ .name = "io_uring_register", .sysno = 427, { 0 } } , 	/* 427 */
	{ .name = "open_tree", .sysno = 428, { 0 } } , 	/* 428 */
	{ .name = "move_mount", .sysno = 429, { 0 } } , 	/* 429 */
	{ .name = "fsopen", .sysno = 430, { 0 } } , 	/* 430 */
	{ .name = "fsconfig", .sysno = 431, { 0 } } , 	/* 431 */
	{ .name = "fsmount", .sysno = 432, { 0 } } , 	/* 432 */
	{ .name = "fspick", .sysno = 433, { 0 } } , 	/* 433 */
	{ .name = "pidfd_open", .sysno = 434, { 0 } } , 	/* 434 */
	{ .name = "clone3", .sysno = 435, { 0 } } , 	/* 435 */
	{ .name = "close_range", .sysno = 436, { 0 } } , 	/* 436 */
	{ .name = "openat2", .sysno = 437, { 0 } } , 	/* 437 */
	{ .name = "pidfd_getfd", .sysno = 438, { 0 } } , 	/* 438 */
	{ .name = "faccessat2", .sysno = 439, { 0 } } , 	/* 439 */
	{ .name = "process_madvise", .sysno = 440, { 0 } } , 	/* 440 */
	{ .name = "epoll_pwait2", .sysno = 441, { 0 } } , 	/* 441 */
	{ .name = "mount_setattr", .sysno = 442, { 0 } } , 	/* 442 */
	{ .name = "quotactl_fd", .sysno = 443, { 0 } } , 	/* 443 */
	{ .name = "landlock_create_ruleset", .sysno = 444, { 0 } } , 	/* 444 */
	{ .name = "landlock_add_rule", .sysno = 445, { 0 } } , 	/* 445 */
	{ .name = "landlock_restrict_self", .sysno = 446, { 0 } } , 	/* 446 */
	{ .name = "memfd_secret", .sysno = 447, { 0 } } , 	/* 447 */
	{ .name = "process_mrelease", .sysno = 448, { 0 } } , 	/* 448 */
	{ .name = "futex_waitv", .sysno = 449, { 0 } } , 	/* 449 */
	{ .name = "set_mempolicy_home_node", .sysno = 450, { 0 } } , 	/* 450 */
};

#endif

