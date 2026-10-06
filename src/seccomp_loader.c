#define _GNU_SOURCE
#include <sched.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <poll.h>
#include <limits.h>
#include <fcntl.h>
#include <signal.h>
#include <dirent.h>

#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/mman.h>

#include <mosquitto.h>
#include <seccomp.h>
#include "rasmo_mqtt.h"
#include "rasmo_hashmap.h"

#include "rasmo_util.h"
#include "seccomp_json.h"
#include "seccomp_util.h"
#include "seccomp_common.h"
#include "seccomp_rt_parser.h"

#define JSON_ERROR_NULL(val, ...)\
	if (!val) {\
		fprintf(stderr, __VA_ARGS__);\
		fprintf(stderr, "ERROR: %s\n", json_util_get_last_err());\
		ret = -1; goto out;\
	}

static char exe_path[PATH_MAX] = { 0 };
static char **exe_args = NULL;

static struct mosquitto *mosq = NULL;
static char *anomaly_topic = "global/cpsp/report/syscall";

volatile sig_atomic_t signal_recvd = 0;
static void signal_handler(int sig)
{
	(void)sig;
	signal_recvd = 1;
}

/* init handlers and block SIGINT & SIGTERM */
static int init_sighandler(sigset_t *org)
{
	int ret = 0;
	struct sigaction sa = { 0 };
	sigset_t block_set, org_set;

	sa.sa_handler = signal_handler;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	/* sigmask: only let ppoll() to receive the unblocked signals */
	sigemptyset(&block_set);
	sigaddset(&block_set, SIGINT);
	sigaddset(&block_set, SIGTERM);

	ret = sigprocmask(SIG_BLOCK, &block_set, &org_set);
	if (ret) {
		perror("sigprocmask failed:");
		ret = -1;
		goto out;
	}

	*org = org_set;

out:
	return ret;
}

static int generate_anomaly_payload(char *exe, char *token, char *result, char **output)
{
	int ret = 0;
	char *specifier = "{\"exe\":\"%s\",\"token\":\"%s\",\"action\":\"%s\"}";
	int len = INIT_BUF_LEN * 2;

	char *anomaly = calloc(len, sizeof(char));
	if (!anomaly) {
		perror("calloc:");
		ret = -1;
		goto out;
	}

	if (snprintf(anomaly, len, specifier, exe, token, result) >= len) {
		ret = -1;
		fprintf(stderr, "%s: invalid payload: %s\n", __func__, anomaly);
		goto out;
	}
	*output = anomaly;

out:
	if (ret) free(anomaly);
	return ret;
}

static int validate_syscall(int fd, struct hmap *map, struct seccomp_notif *req, struct seccomp_notif_resp *resp)
{
	int ret = 0, result = 0;
	char token[INIT_BUF_LEN] = { 0 };

	/* load parse function */
	ret = runtime_tokenizer(fd, req, token);
	if (ret) {
		if (ret == -1)
			fprintf(stderr, "%s: parse failed\n", __func__);
		goto out;
	}

//fprintf(stderr, "pid: %d Token: %s\n", req->pid, token);

	/* query hmap */
	result = hmap_lookup_elem(token, map, NULL);
	if (result > 0) {
		resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
		/* error and val must be zero */
		resp->error = 0;
		resp->val = 0;
	} else {
		/* spoofed failure */
		resp->flags = 0;
		resp->error = -EPERM;
//DEBUG
//fprintf(stderr, "%s failed\n", token);

#ifdef ENABLE_COLLAB
		/* report anomaly if the call is rejected */
		if (!resp->flags) {
			char *anomaly = NULL;

			ret = generate_anomaly_payload(exe_path, token, "EPERM", &anomaly);
			if (ret) {
				fprintf(stderr, "%s: Failed to generate anomaly payload\n", __func__);
				ret = -1;
				goto out;
			}

			ret = mqtt_publish(mosq, anomaly_topic, strlen(anomaly), anomaly, 2);
			if (ret) {
				fprintf(stderr, "Failed to publish %s to topic %s\n", token, anomaly_topic);
				ret = -1;
				goto out;
			}
			free(anomaly);
		}
#endif
	}

	resp->id = req->id;

out:
	return ret;
}

static int generate_args_rule_array(int num_args, struct syscall_arg *args,
								int *num_rules, struct scmp_arg_cmp **array_p)
{
	int ret = 0, i;
	int num = 0;

	/* if no args, skip */
	if (!args || !num_args) {
		*num_rules = 0;
		*array_p = NULL;
		goto out;
	}

	struct scmp_arg_cmp *args_array = calloc(num_args, sizeof(struct scmp_arg_cmp));
	if (!args_array) {
		perror("Failed to allocate mem for args array:");
		ret = -1;
		goto out;
	}

	/* load all the arg rules into a scmp_arg_cmp array */
	for (i = 0; i < num_args; i++) {
		struct syscall_arg *cur_arg = &args[i];
		struct scmp_arg_cmp *cur_cmp = &args_array[num];

		int idx = cur_arg->idx;
		enum arg_type type = cur_arg->type;
		uint64_t value = cur_arg->value;
		int op = cur_arg->op;

		/* skip pointer type of arguments, which shouldn't be here */
		if (type == PTR_ARG) continue;

		/* SCMP_CMP_MASKED_EQ is skipped for now */
		*cur_cmp = SCMP_CMP(idx, op, value);
		num++;
	}

	/* resize */
	if (num != num_args) {
		struct scmp_arg_cmp *tmp = NULL;

		tmp = realloc(args_array, sizeof(struct scmp_arg_cmp)*num);
		if (!tmp) {
			ret = -1;
			fprintf(stderr, "%s: Failed to realloc mem for rule array\n", __func__);
			free(args_array); goto out;
		}
		args_array = tmp;
	}

	*num_rules = num;
	*array_p = args_array;

out:
	return ret;
}

static int add_default_rules(scmp_filter_ctx ctx)
{
	int ret = 0;

//	/* clone */
//	ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clone),
//			1, SCMP_A0(SCMP_CMP_EQ,
//			CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD));
//	if (ret) {
//		fprintf(stderr, "%s: seccomp_rule_add(%d) failed: %s\n",
//			__func__, SCMP_SYS(clone), strerror(errno));
//		goto out;
//	}
//
	/* wait4 */
	ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(wait4), 0);
	if (ret) {
		fprintf(stderr, "%s: seccomp_rule_add(%d) failed: %s\n",
			__func__, SCMP_SYS(wait4), strerror(errno));
		goto out;
	}

	/* rt_sigreturn */
	ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
	if (ret) {
		fprintf(stderr, "%s: seccomp_rule_add(%d) failed: %s\n",
			__func__, SCMP_SYS(rt_sigreturn), strerror(errno));
		goto out;
	}

	/* sched_yield for multithreading */
	ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_yield), 0);
	if (ret) {
		fprintf(stderr, "%s: seccomp_rule_add(%d) failed: %s\n",
			__func__, SCMP_SYS(sched_yield), strerror(errno));
		goto out;
	}

	/* exit */
	ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
	if (ret) {
		fprintf(stderr, "%s: seccomp_rule_add(%d) failed: %s\n",
			__func__, SCMP_SYS(exit), strerror(errno));
		goto out;
	}

out:
	return ret;
}

static int send_fd(int sock, int fd)
{
	int ret = 0;
	int dummy_data = 1;
	struct msghdr msg = { 0 };
	struct cmsghdr *cmsg = NULL;
	struct iovec iov = { 0 };
	char cmsgbuf[CMSG_SPACE(sizeof(int))] = { 0 };
	
	iov.iov_base = &dummy_data;
	iov.iov_len = sizeof(dummy_data);

	/* init msghdr */
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);

	/* send notify FD */
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;

	msg.msg_controllen = cmsg->cmsg_len;

	*((int *)CMSG_DATA(cmsg)) = fd;

	ret = sendmsg(sock, &msg, 0);
	if (ret < 0) {
		ret = -1;
		perror("Failed to sendmsg:");
		goto out;
	}

	ret = 0;

out:
	return ret;
}

static int recv_fd(int sock, int *p_fd)
{
	int ret = 0;
	int dummy_data = 1;
	struct msghdr msg = { 0 };
	struct cmsghdr *cmsg = NULL;
	struct iovec iov = { 0 };
	char cmsgbuf[CMSG_SPACE(sizeof(int))] = { 0 };

	iov.iov_base = &dummy_data;
	iov.iov_len = sizeof(dummy_data);

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);

	ret = recvmsg(sock, &msg, MSG_WAITALL);
	if (ret < 0) {
		ret = -1;
		perror("recvmsg() failed:");
		goto out;
	}

	cmsg = CMSG_FIRSTHDR(&msg);

	if (!cmsg || cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS) {
		fprintf(stderr, "%s: Invalid control message\n", __func__);
		ret = -1;
		goto out;
	}

	/* received notify file descriptor */
	*p_fd = *(int *)CMSG_DATA(cmsg);
	ret = 0;

out:
	return ret;
}

void usage(char *argv0)
{
	fprintf(stderr, "%s -i <profile_path> -- <app_path> <arg-list>\n", argv0);
}

int main(int argc, char **argv)
{
	int ret = 0, i;
	char *profile_path = NULL;
	int opt = 0;
	int status = 0;
	int pid_1 = -1;
	int arg_idx = 0;
	struct hmap *map = NULL;

	while ((opt = getopt(argc, argv, "i:")) != -1) {
		switch (opt) {
			case 'i':
				profile_path = optarg;
				break;
			default:
				fprintf(stderr, "Invalid argument: %c\n", optopt);
				usage(argv[0]);
				goto out;
		}
	}

	if (!profile_path) {
		profile_path = OUTPUT_DIR;
	}

	/* parse target app path and its args
	-- leaves optind pointing past it */
	// NULL marks the final element
	exe_args = calloc(argc - optind + 1, sizeof(char *));
	if (!exe_args) {
		fprintf(stderr, "Failed to alloc for args array\n");
		ret = -1;
		goto out;
	}

	/* absolute path, pass to the buf directly */
	const char *exe_p = argv[optind];
	if (exe_p) {
		if (exe_p[0] == '/') {
			if (strlen(exe_p) >= PATH_MAX) {
				fprintf(stderr, "path longer than PATH_MAX\n");
				ret = -1;
				goto out;
			}
			snprintf(exe_path, PATH_MAX, "%s", exe_p);
		}
		else {
			/* get absolute path of the binary */
			if (resolve_abs_path(exe_p, (char *)exe_path)) {
				fprintf(stderr, "Failed to find the binary: %s\n", exe_p);
				ret = -1;
				goto out;
			}
		}
	}
	else {
		usage(argv[0]);
		goto out;
	}

	for (i = optind; i < argc; i++) {
		exe_args[arg_idx++] = argv[i];
	}
	exe_args[0] = exe_path;
	exe_args[arg_idx] = NULL;

	/* supervisor the reaper */
	ret = prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);
	if (ret < 0) {
		ret = -1;
		perror("prctl failed:");
		goto out;
	}

	/* prepare socket between parent-child */
	int sock[2] = { 0 };
	ret = socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sock);
	if (ret < 0) {
		perror("socketpair failed:");
		goto out;
	}

	/* set both socket close-on-exec */
	for (i = 0; i < 2; i++) {
		int flags = fcntl(sock[i], F_GETFD);
		ret = fcntl(sock[i], F_SETFD, flags | FD_CLOEXEC);
		if (ret < 0) {
			perror("Failed to set FD_CLOEXEC on socket:");
			goto out;
		}
	}


	pid_1 = fork();
	if (pid_1 > 0) {
		/* parent: handles notify */
		close(sock[1]);

		char token_path[PATH_MAX] = { 0 };
		// find *.tok from the profile directory
		DIR *dir = NULL; struct dirent *entp = NULL;
		dir = opendir(profile_path);
		if (!dir) {
			fprintf(stderr, "Failed to open %s\n", profile_path);
			goto out;
		}
	
		while ((entp = readdir(dir))) {
			char *name = entp->d_name;
			int len = strlen(name);
			if (len < 5 ||
			   strcmp(name + len - 4, ".tok")) {
				continue;
			}
	
			// found
			snprintf(token_path, PATH_MAX, "%s/%s", profile_path, name);
			ret = load_hmap_from_file(token_path, &map);
			if (ret) {
				fprintf(stderr, "Failed to load hmap\n");
				goto out;
			}
			break;
		}
		closedir(dir);

		// app
		ret = load_hmap_from_file(token_path, &map);
		if (ret) {
			fprintf(stderr, "Failed to load hmap\n");
			goto out;
		}

		ret = init_dyn_path_list(NULL);
		if (ret) {
			fprintf(stderr, "Failed to load dynamic path list\n");
			goto out;
		}

		int fd = -1;
		ret = recv_fd(sock[0], &fd);
		if (ret) {
			fprintf(stderr, "Failed to receive notifier fd\n");
			goto out;
		}

#ifdef ENABLE_COLLAB
		/* connect to the local coordinator */
		mosq = mqtt_init("localhost", 1883, 60, NULL, NULL, NULL, NULL);
		if (!mosq) {
			fprintf(stderr, "mqtt_init failed\n");
			ret = -1;
			goto out;
		}
		mqtt_loop_start(mosq);
#endif
		sigset_t org_set;

		/* block SIGINT and SIGTERM */
		ret = init_sighandler(&org_set);
		if (ret) {
			fprintf(stderr, "Failed to set signal mask\n");
			goto out;
		}

		struct timespec timeout = {
			.tv_sec = 2,
			.tv_nsec = 0
		};

		/* poll() the FD for notifications */
		struct pollfd notification = { 0 };
		notification.fd = fd;
		notification.events = POLLIN;

		int ret_wait = 0;
		/* stop polling if error occurs or child has exited */
		while (!(ret_wait = waitpid(pid_1, &status, WNOHANG))) {
			/* if waitpid failure or the superviosr received SIGINT or SIGTERM,
				kill the child process */
			if (signal_recvd) {
				kill(pid_1, SIGKILL);
				goto out;
			}

			/* ppoll() from the child with unblocked SIGINT and SIGTERM;
				handler only fires here
			*/
			ret = ppoll(&notification, 1, &timeout, &org_set);
			if (ret < 0) {
				/* interrupted by signal */
				if (errno == EINTR) continue;

				perror("poll failed:");
				goto out;
			} else if (!ret) {
				/* if timeout, continue to next loop */
				continue;
			}

			/* for POLLERR, POLLHUP or POLLNVAL */
			if (!(notification.revents & POLLIN)) break;

    		struct seccomp_notif *req = NULL;
    		struct seccomp_notif_resp *resp = NULL;

			ret = seccomp_notify_alloc(&req, &resp);
			if (ret) {
				perror("Parent failed to alloc notify:");
				goto sv_err;
			}
	
			ret = seccomp_notify_receive(fd, req);
			if (ret) {
				perror("Parent failed to receive notify:");
				goto sv_err;
			}

			/* verify notify */
			ret = validate_syscall(fd, map, req, resp);
			if (ret) {
				if (ret == -2) {
					seccomp_notify_free(req, resp);
					continue;
				}
				fprintf(stderr, "Failed to validate syscall %d\n", req->data.nr);
				goto sv_err;
			}

			/* respond */
			ret = seccomp_notify_respond(fd, resp);
			if (ret) {
				perror("Parent failed to respond:");
				goto sv_err;
			}

			ret = 0;
sv_err:
			seccomp_notify_free(req, resp);
			if (ret) goto out;
		}

		/* check waitpid error */
		if (ret_wait < 0 && errno != ECHILD) {
			fprintf(stderr, "waitpid error for %d\n", pid_1);
			ret = -1;
			goto out;
		}

	} else if (!pid_1) {
		/* init seccomp and load app */
		close(sock[0]);

		int fd = 0;
		int list_len = 0;
		struct profile_syscall *rule_list = NULL;
		uint32_t default_action = 0;
		char json_path[PATH_MAX] = { 0 };
		DIR *dir = NULL; struct dirent *entp = NULL;

		dir = opendir(profile_path);
		if (!dir) {
			fprintf(stderr, "Failed to open %s\n", profile_path);
			goto out;
		}
	
		while ((entp = readdir(dir))) {
			char *name = entp->d_name;
			int len = strlen(name);
			if (len < 6 ||
			   strcmp(name + len - 5, ".json")) {
				continue;
			}
	
			// found
			snprintf(json_path, PATH_MAX, "%s/%s", profile_path, name);
		}
		closedir(dir);

		/* load profile from JSON */
		ret = load_json_profile(json_path, &default_action,
				(void **)&rule_list, &list_len);
		if (ret) {
			fprintf(stderr, "Failed to load filter from JSON\n");
			_exit(EXIT_FAILURE);
		}

		/* 	use a helper process to send file descriptor;
			the notify fd is passed to the helper through 
			shared memory; Reference to libcrun: seccomp.c
		*/
		volatile int *fd_share = NULL;
		void *mem_addr = mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE,
							 MAP_SHARED | MAP_ANONYMOUS, -1, 0);
		if (mem_addr == MAP_FAILED) {
			perror("mmap failed:");
			_exit(EXIT_FAILURE);
		}
		fd_share = mem_addr;
		*fd_share =  -1;

		/* create helper process */
		pid_t h_pid = syscall(__NR_clone, CLONE_FILES | SIGCHLD, NULL);
		if (h_pid < 0) {
			perror("failed to clone helper process:");
			_exit(EXIT_FAILURE);
		}
		else if (!h_pid) {
			/* helper process wait for the fd and send to the supervisor */

			prctl(PR_SET_PDEATHSIG, SIGKILL);

			/* check if the fd is ready */
			while (*fd_share == -1) {
				usleep(1000);
				continue;
			}

			/* fd has been written to the shared memory */
			fd = *fd_share;

			/* send to the socket */
			ret = send_fd(sock[1], fd);
			if (ret) {
				fprintf(stderr, "Failed to send notify fd\n");
				_exit(EXIT_FAILURE);
			}

			/* helper exits */
			exit(EXIT_SUCCESS);
		}
		else {
			/* init seccomp and notifier */
			scmp_filter_ctx ctx = seccomp_init(default_action);
			if (!ctx) {
				perror("seccomp_init() failed:");
				_exit(EXIT_FAILURE);
			}

			ret = seccomp_attr_set(ctx, SCMP_FLTATR_CTL_LOG, 1);
			if (ret) {
				perror("seccomp_attr_set:");
				_exit(EXIT_FAILURE);
			}

			ret = add_default_rules(ctx);
			if (ret) {
				fprintf(stderr, "Failed to add default seccomp rules\n");
				_exit(EXIT_FAILURE);
			}

			for (i = 0; i < list_len; i++) {
				struct profile_syscall *cur_profile = &rule_list[i];
				int sysno = cur_profile->sysno;
				uint32_t action = cur_profile->action;
				struct syscall_arg *args = cur_profile->args;
	
				/* if NOTIFY, args is NULL */
				int num_args = (args)? cur_profile->num_args : 0;
				int num_rules = 0;
	
				struct scmp_arg_cmp *cmp_array = NULL;
	
				ret = generate_args_rule_array(num_args, args, &num_rules, &cmp_array);
				if (ret) {
					fprintf(stderr, "Failed to allocate rule array\n");
					_exit(EXIT_FAILURE);
				}
	
				ret = seccomp_rule_add_array(ctx, action, sysno, num_rules, cmp_array);
				if (ret) {
					perror("seccomp_rule_add_array() failed:");
					_exit(EXIT_FAILURE);
				}
	
				if (cmp_array) free(cmp_array);
			}
	
			/* don't need rule list after regsitration */
			free(rule_list);

// output registered rules in readable format
#ifdef DEBUG
int filter_fd = 0;
char debug_path[PATH_MAX] = { 0 };
snprintf(debug_path, PATH_MAX, "%s/filter.pfc", profile_path);
filter_fd = open(debug_path, O_WRONLY|O_CREAT|O_TRUNC, 0644);
if (filter_fd == -1) {
	fprintf(stderr, "Failed to open file: %s\n", strerror(errno));
	goto out;
} 
seccomp_export_pfc(ctx, filter_fd);
close(filter_fd);
#endif

			ret = seccomp_load(ctx);
			if (ret < 0) {
				perror("seccomp_load() failed:");
				_exit(EXIT_FAILURE);
			}
	
			fd = seccomp_notify_fd(ctx);
			if (fd < 0) {
				perror("seccomp_notify_fd failed:");
				_exit(EXIT_FAILURE);
			}

			*fd_share = fd;

			/* wait for the child */
			pid_t w_pid;
			do {
				w_pid = waitpid(h_pid, &status, 0);
			} while (w_pid < 0 && errno == EINTR);

			/* unmap the shared memory */
			munmap(mem_addr, sizeof(int));
		}
		/*
			if not an absolute path, execvp will search in PATH and 
		 	make multiple execve() system calls, which will cause
		 	seccomp fail its verification
		*/

		execvp(exe_path, exe_args);

		/* failure if reaches here */
		perror("Execve failed:");
		_exit(127);
	} else {
		perror("fork() failed: ");
		ret = -1;
		goto out;
	}

	ret = 0;

out:
	/* reap all the child processes */
	if (pid_1 > 0) {
		/* if error occured in the supervisor, kill the child process */
		if (ret) kill(pid_1, SIGKILL);
		while (waitpid(-1, &status, 0) > 0) ;
	}
	if (mosq) {
		mqtt_loop_stop(mosq, 1);
		mqtt_finalize(mosq);
	}
	hmap_finalize(map);
	free(exe_args);

	return ret;
}
