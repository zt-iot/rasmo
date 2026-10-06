#define _GNU_SOURCE
#define __USE_GNU
#include <sched.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libaudit.h>
#include <auparse.h>
#include <getopt.h>
#include <pthread.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <sys/syscall.h>
#include <linux/sched.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <errno.h>
#include <assert.h>
#include <time.h>

#include "rasmo_util.h"
#include "rasmo_mqtt.h"
#include "audit_plugin_lib.h"

pid_t mypid = -1;
auparse_state_t *au = NULL;
void *mqtt_inst = NULL;

#define MSG_LEN_MAX ( MAX_AUDIT_MESSAGE_LENGTH + 128 )

static inline int get_field_value(auparse_state_t *au, char *key) {
	const char *field = NULL;
	const char *record = auparse_get_record_text(au);
	if (!record) return -1;

	auparse_first_field(au);
	field = auparse_find_field(au, key);
	if (!field) {
//		fprintf(stderr, "Record %s: Unable to find %s\n", record, key);
		return -1;
	}
	return auparse_get_field_int(au);
}

static inline const char *get_raw_string(auparse_state_t *au, char *key) {
	const char *field = NULL; 
	auparse_first_field(au);
	field = auparse_find_field(au, key);
	if (!field) {
		return "NULL";
	}

	return auparse_get_field_str(au);
}

// SYSCALL, MMAP, CWD, PATH EXECVE record 
// SYSCALL: arch=c00000b7 syscall=48 success=no exit=-2 a0=ffffffffffffff9c a1=7f80efc9c0 a2=4 a3=314f8 items=1 ppid=55716 pid=57272 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=3450 comm="libcamera-hello" exe="/usr/bin/libcamera-hello" key=(null)ARCH=aarch64 SYSCALL=faccessat AUID="jie" UID="jie" GID="jie" EUID="jie" SUID="jie" FSUID="jie" EGID="jie" SGID="jie" FSGID="jie" 
// EXECVE argc=2 a0="libcamera-hello" a1="--qt-preview"
// MMAP: fd=6 flags=0x812
// CWD: cwd="/home/jie/Documents/audit/poc-tmp/src/camera"
// PATH: item=0 name="/usr/bin/libcamera-hello" inode=24867 dev=b3:02 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0 OUID="root" OGID="root"

#define string_compare(str1, str2) ({\
	int ret = 0;\
	int len_str1 = strlen(str1);\
	int len_str2 = strlen(str2);\
	if (len_str1 != len_str2) { ret = -1; }\
	else { ret = (memcmp(str1, str2, len_str1))? -1 : 0; }\
	ret;\
})

static void handle_event(auparse_state_t *au, auparse_cb_event_t cb_event_type, void *user_data)
{
	int offset = 0, len = 0, nrec = 0;
	int syscall_status = 0, syscall = -1;
	int ret = 0;

	(void)user_data;

	char msg_buf[MSG_LEN_MAX] = { 0 };
	char topic_name[MQTT_TOPIC_LEN_MAX] = { 0 };
	const char *exe_name = NULL;
	char *hex_exe_name = NULL;
	pid_t pid = -1;

	if (cb_event_type != AUPARSE_CB_EVENT_READY)
		return;

	while (auparse_goto_record_num(au, nrec++) > 0) {
		const char *record = auparse_get_record_text(au);
		if (!record) continue;

		int type = auparse_get_type(au);

		if (type == AUDIT_USER_AUTH) {
			/* for dropbear ssh server */
			const char *result = NULL, *username = NULL, *valid_user = NULL;
			const char *fingerprint = NULL;
			const char *ip_addr = NULL;

			valid_user = get_raw_string(au, "valid_user");
			fingerprint = get_raw_string(au, "fingerprint");
			username = get_raw_string(au, "acct");
			ip_addr = get_raw_string(au, "addr");

			result = get_raw_string(au, "res");
			sprintf(topic_name, "local/audit/login/%s", result);

			if (!strcmp(result, "failed")) {
				offset = snprintf(msg_buf, MSG_LEN_MAX, "username=%s valid_user=%s fingerprint=%s ip_addr=%s",
					username, valid_user, fingerprint, ip_addr);
			}
			else {
				offset = snprintf(msg_buf, MSG_LEN_MAX, "username=%s fingerprint=%s ip_addr=%s",
					username, fingerprint, ip_addr);
			}

			if (mqtt_inst) {
				mqtt_publish(mqtt_inst, topic_name, offset, msg_buf, 1);
			}

			memset(topic_name, 0, MQTT_TOPIC_LEN_MAX);
			memset(msg_buf, 0, MSG_LEN_MAX);
			offset = 0;

			continue;
		}
		// syscall record
		if (type == AUDIT_SYSCALL) {
			int i;  
			const char *success = NULL;
			const char *args[4] = { 0 };

			syscall = get_field_value(au, "syscall");
			pid = get_field_value(au, "pid");

			exe_name = get_raw_string(au, "exe");
			success = get_raw_string(au, "success");
			syscall_status = string_compare(success, "yes");

			ret = encode_exe_name(exe_name, &hex_exe_name);
			if (ret) {
				fprintf(stderr, "Failed to encode name %s from %s\n", exe_name, record);
				return ;
			}

			for (i = 0; i < 4; i++) {
				char key[4] = { 0 };
				sprintf(key, "a%d", i);

				args[i] = get_raw_string(au, key); 
			}

			// success: 0 yes, -1 no 
			//len = sprintf(msg_buf+offset, "syscall=%d success=%d msg_no=%d",
			//	syscall, syscall_status, cur_exe->msg_counter);
			len = sprintf(msg_buf+offset, "syscall=%d success=%d",
				syscall, syscall_status);
			offset += len;

			// args
			for (i = 0; i < 4; i++) {
				len = sprintf(msg_buf+offset, " a%d=%s", i, args[i]);
				offset += len;
			}
		}
		// execve record
		else if (type == AUDIT_EXECVE) {
			int ex_argc = 0, i;
			char a0_resolved[PATH_MAX] = { 0 };
			
			ex_argc = get_field_value(au, "argc");
			len = sprintf(msg_buf+offset, " argc=%d", ex_argc);
			offset += len;

			auparse_first_field(au);

			if (auparse_find_field(au, "a0")) {
				const char *a0_str = auparse_interpret_field(au);
				ret = resolve_abs_path(a0_str, a0_resolved);
				if (ret) {
					fprintf(stderr, "Failed to resolve: %s in %s\n", a0_str, record);
					return;
				}
				len = sprintf(msg_buf+offset, " exe_a0=%s", a0_resolved);
				offset += len;
			}
			else {
				fprintf(stderr, "%s: missing a0 field in %s\n", __func__, record);
				return ;
			}

			char opt_list[MSG_LEN_MAX] = { 0 };
			char *opt_start = opt_list;

			for (i = 1; i < ex_argc; i++) {
				const char *arg = NULL;
				char key[32] = { 0 };
				int bufsize = MSG_LEN_MAX - (int)(opt_start - opt_list);

				sprintf(key, "a%d", i);

				if (auparse_find_field(au, key)) {
					arg = auparse_interpret_field(au);
				}
				else {
					fprintf(stderr, "%s: error in parsing args(%d): %s\n", __func__, i, record);
					return;
				}

				ret = snprintf(opt_start, bufsize, "%s", arg);
				if (ret < 0 || ret >= bufsize) {
					fprintf(stderr, "%s: invalid execve arg: %s\n", __func__, record);
					return;
				}
				opt_start += strlen(arg);
			}

			opt_start = (strlen(opt_list))? opt_list : NULL_STR;
			offset += sprintf(msg_buf+offset, " exe_opt=%s", opt_start);
		}
		// SOCKADDR
		else if (type == AUDIT_SOCKADDR) {
			const char *saddr = get_raw_string(au, "saddr");

			len = sprintf(msg_buf+offset, " saddr=%s", saddr);
			offset += len;
		}
		// mmap record
		else if (type == AUDIT_MMAP) {
			int fd = get_field_value(au, "fd");
			const char *flag = get_raw_string(au, "flags");

			len = sprintf(msg_buf+offset, " mmap_fd=%d mmap_flags=%s",
				fd, flag);
			offset += len;
		}
		// path record: execve generates two PATH records:
		// 	one for the executable
		//	the other is for the loader
		else if (type == AUDIT_PATH) {
			// openat: if empty file name, there was no PATH record generated
			// if the system call failed, no recording file info
			const char *nametype = get_raw_string(au, "nametype");
			if (!strcmp(nametype, "NORMAL") || !strcmp(nametype, "UNKNOWN")) {
				const char *file_name = get_raw_string(au, "name");
				//if (!strcmp(file_name, "\"\"") || !strcmp(file_name, "(null)")) continue;

				len = sprintf(msg_buf+offset, " file=%s", file_name);
				offset += len;

//				if (syscall_status != 0) continue;

				const char *inode = NULL;
				const char *dev = NULL;
				const char *mode = NULL;

				inode = get_raw_string(au, "inode");
				dev = get_raw_string(au, "dev");
				mode = get_raw_string(au, "mode");

				len = sprintf(msg_buf+offset, " inode=%s dev=%s mode=%s",
						inode, dev, mode);
				offset += len;
			}
		}
	}

	if (offset) {
		if (mqtt_inst) {
			// encode topic name
			sprintf(topic_name, "local/audit/syscall/%s/%d", hex_exe_name, pid);

			mqtt_publish(mqtt_inst, topic_name, offset, msg_buf, 2);
		}
	}

	free(hex_exe_name);
}

static int print_pid_schepolicy(pid_t pid)
{
    int policy = sched_getscheduler(pid);

    switch(policy) {
        case SCHED_OTHER: fprintf(stderr, "SCHED_OTHER\n"); break;
        case SCHED_RR:   fprintf(stderr, "SCHED_RR\n"); break;
        case SCHED_FIFO:  fprintf(stderr, "SCHED_FIFO\n"); break;
        default:   fprintf(stderr, "Unknown...\n");
    }
	
	return policy;
}

int main(int argc, char **argv)
{
	int rc = 0;
	ssize_t msg_len = 0;
	char message[MAX_AUDIT_MESSAGE_LENGTH] = { 0 };
	unsigned int cpu = 0;

	(void)argc;

	getcpu(&cpu, NULL);
	mypid = getpid();
	print_pid_schepolicy(mypid);

	fprintf(stderr, "plugin@CPU %d PID: %d\n", cpu, mypid);

	rc = plugin_init(argv[1], &mqtt_inst, &au, handle_event);
	if (rc) {
		fprintf(stderr, "Test initialization failed!\n");
		goto out;
	}

	/* start auparsing */
	do {
		if (auparse_feed_has_data(au)) {
			// check events for complete based on time 
			// if there's data
			auparse_feed_age_events(au);
		}

		while ((msg_len = read(0, message, MAX_AUDIT_MESSAGE_LENGTH - 1)) > 0) {
			message[msg_len] = '\0';
			auparse_feed(au, message, msg_len);
		} 
	} while (!hup && !stop);

	auparse_flush_feed(au);

out:
	plugin_finalize(au, mqtt_inst);

	return 0;
}
