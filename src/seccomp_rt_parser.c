#define _GNU_SOURCE
#include <fcntl.h>
#include <limits.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <seccomp.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/sysmacros.h>

#include "rasmo_sysname.h"
#include "rasmo_util.h"
#include "seccomp_util.h"
#include "seccomp_rt_parser.h"

#define formalize_fd_str(_fd, out_str) ({\
	int len = 0;\
	if (_fd == 0xffffff9c) {\
		len = sprintf(out_str, "%016llx", (long long int)AT_FDCWD);\
	} else {\
		len = sprintf(out_str, "%llx", _fd);\
	}\
	out_str[len] = '\0';\
	len;\
})

static int open_pid_mem(int pid)
{
	int fd = 0;
	char mem_path[PATH_MAX] = { 0 };

	snprintf(mem_path, PATH_MAX, "/proc/%d/mem", pid);
	fd = open(mem_path, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "%s: Failed to open %s error: %s\n",
			__func__, mem_path, strerror(errno));
		fd = -1;
	}

	return fd;
}

/* assume that space is already allocated for token */
int runtime_tokenizer(int notif_fd, void *req, char *token)
{
	int ret = 0;
	struct seccomp_notif *notif = (struct seccomp_notif *) req;
	struct seccomp_data *data = &notif->data;
	__u64 id = notif->id; __u32 pid = notif->pid;
	int sysno = data->nr;
	__u64 *args = data->args;
	int mem_fd = -1;
	rt_func_ptr parser = get_parse_func(sysno, rt);

	/* open target process memory */
	mem_fd = open_pid_mem(pid);
	if (mem_fd < 0) {
		fprintf(stderr, "%s: Failed to open target memory file\n", __func__);
		ret = -1;
		goto out;
	}

	/*  validate seccomp request ID
		NOTE: invalid ID doesnt mean the tracee process has died.
		according to the manual, after opening any resources
		relevant to the pid for a notification (e.g., /proc/pid/mem)
		should call this func to make sure that the resources the 
		application has opened correspond to the right pid, i.e. the
		pid didn't die and got reused by another task.
	*/
	if (seccomp_notify_id_valid(notif_fd, id) == -ENOENT) {
		/* FIXME: need to distinguish return value
			this looks ugly */
		ret = -2;
		goto out;
	}

	/* load parser function */
	if (parser) {
		ret = parser(mem_fd, args, token);
		if (ret) {
			fprintf(stderr, "Parse failed\n");
			goto out;
		}
	}
	else {
		fprintf(stderr, "%s: no parse function exist for syscall %d\n", __func__, sysno);
		ret = -1;
		goto out;
	}

out:
	if (mem_fd >= 0) close(mem_fd);
	return ret;
}

static void encode_file_header(char *path, char *processed_path, char *header_output)
{
	int ret = 0, len = 0;
	struct stat file_stat = { 0 };
	int file_exist = 1;
	char final_path[PATH_MAX] = { 0 };
	char encode[FILE_HEADER_LEN] = { 0 };

	ino_t inode = 0; mode_t mode = 0;
	int dev_major = 0, dev_minor = 0;

	file_exist = process_path(path, final_path);
	if (file_exist) {
		/* including metadata */
		ret = stat(final_path, &file_stat);
		if (ret) {
			file_exist = 0;
		} else {
			inode = file_stat.st_ino;
			dev_major = major(file_stat.st_dev);
			dev_minor = minor(file_stat.st_dev);
			mode = file_stat.st_mode;
		}
	} 

	len += sprintf(encode, "%s", final_path);
	if (file_exist) {
		len += sprintf(encode+len, ":i=%ld:d=%02x-%02x:m=%#o",
				inode, dev_major, dev_minor, mode);
	}

	if (processed_path)
		memcpy(processed_path, final_path, PATH_MAX);

	memcpy(header_output, encode, len);
	header_output[len] = '\0';
}

/* Token format:
	fn=<path w/o quote>:i=<inode>:d=<major>:<minor>:m=<mode>:
*/
static int _file_info_parse(int mem_fd, __u64 addr, char *final_path, char *header)
{
	int ret = 0;
	char raw_path[PATH_MAX] = { 0 };

	ret = lseek(mem_fd, addr, SEEK_SET);
	if (ret == -1) {
		fprintf(stderr, "%s: Failed to access addr %llx: %s\n",
			__func__, addr, strerror(errno));
		goto out;
	}

	ret = read(mem_fd, raw_path, PATH_MAX-1);
	if (ret == -1) {
		fprintf(stderr, "%s: Failed to read from %llx: %s\n",
			__func__, addr, strerror(errno));
		goto out;
	}
	raw_path[PATH_MAX-1] = '\0';

	/* generate file header for the token */
	encode_file_header(raw_path, final_path, header);

	ret = 0;

out:
	return ret;
}

int openat_rt_parse(int mem_fd, __u64 *args, char *token)
{
	int ret = 0;
	__u64 dirfd = args[0];
	__u64 addr = args[1];
	__u64 flags = args[2];
	char file_header[FILE_HEADER_LEN] = { 0 };

	ret = _file_info_parse(mem_fd, addr, NULL, file_header);
	if (ret) {
		fprintf(stderr, "%s: failed to parse file info\n", __func__);
		goto out;
	}
	
	/* a0: process AT_FDCWD */
	char A0[64] = { 0 };
	formalize_fd_str(dirfd, A0);

	ret = sprintf(token, "#%d:a0=%s:a1=%s:a2=%llx", SYSNO(openat),
			A0, file_header, flags);
	token[ret] = '\0';

	ret = 0;

out:
	return ret;
}

int execve_rt_parse(int mem_fd, __u64 *args, char *token)
{
	int ret = 0;
	__u64 addr = args[0];
	__u64 argv = args[1];
	char file_header[FILE_HEADER_LEN] = { 0 };
	char *argv_buf = NULL;

	ret = _file_info_parse(mem_fd, addr, NULL, file_header);
	if (ret) {
		fprintf(stderr, "%s: failed to parse file info\n", __func__);
		goto out;
	}

	argv_buf = calloc(INIT_BUF_LEN, sizeof(char));
	if (!argv_buf) {
		fprintf(stderr, "%s: Failed to calloc: %s\n", __func__, strerror(errno));
		ret = -1;
		goto out;
	}

	int i, len = 0;
	/* skip argv[0] */
	for (i = 1; ; i++) {
		char buf[PATH_MAX] = { 0 };
		__u64 argv_addr = argv + i * sizeof(char *);
		__u64 arg_addr = 0;

		/* get value of each pointer in argv[] */
		ret = lseek(mem_fd, argv_addr, SEEK_SET);
		if (ret == -1) {
			fprintf(stderr, "%s: Failed to access addr %llx: %s\n",
				__func__, argv_addr, strerror(errno));
			goto out;
		}

		ret = read(mem_fd, &arg_addr, sizeof(char *));
		if (ret == -1) {
			fprintf(stderr, "%s: Failed to read from %llx: %s\n",
				__func__, argv_addr, strerror(errno));
			goto out;
		}

		// if meet NULL, end of argv
		if (!arg_addr) break;

		/* read string from each pointed address if not NULL */
		ret = lseek(mem_fd, arg_addr, SEEK_SET);
		if (ret == -1) {
			fprintf(stderr, "%s: Failed to access addr %llx: %s\n",
				__func__, arg_addr, strerror(errno));
			goto out;
		}

		ret = read(mem_fd, buf, PATH_MAX-1);
		if (ret == -1) {
			fprintf(stderr, "%s: Failed to read from %llx: %s\n",
				__func__, arg_addr, strerror(errno));
			goto out;
		}
		buf[PATH_MAX-1] = '\0';

		if (len + strlen(buf) > INIT_BUF_LEN) {
			fprintf(stderr, "%s: not enough buffer for argv\n", __func__);
			ret = -1;
			goto out;
		} else {
			snprintf(argv_buf + len, INIT_BUF_LEN - len, "%s", buf);
			len += strlen(buf);
		}
	}

	ret = sprintf(token, "#%d:a0=%s:a1=%s", SYSNO(execve), file_header,
			strlen(argv_buf)? argv_buf : NULL_STR);
	token[ret] = '\0';

	ret = 0;

out:
	if (argv_buf) free(argv_buf);
	return ret;
}

int faccessat_rt_parse(int mem_fd, __u64 *args, char *token)
{
	int ret = 0;
	__u64 fd = args[0];
	__u64 addr = args[1];
	__u64 mode = args[2];
	char file_header[FILE_HEADER_LEN] = { 0 };

	ret = _file_info_parse(mem_fd, addr, NULL, file_header);
	if (ret) {
		fprintf(stderr, "%s: failed to parse file info\n", __func__);
		goto out;
	}
	
	/* a0: process AT_FDCWD */
	char A0[64] = { 0 };
	formalize_fd_str(fd, A0);

	ret = sprintf(token, "#%d:a0=%s:a1=%s:a2=%llx", 
			SYSNO(faccessat), A0, file_header, mode);
	token[ret] = '\0';

	ret = 0;

out:
	return ret;
}

int statfs_rt_parse(int mem_fd, __u64 *args, char *token)
{
	int ret = 0;
	__u64 addr = args[0];
	char file_header[FILE_HEADER_LEN] = { 0 };

	ret = _file_info_parse(mem_fd, addr, NULL, file_header);
	if (ret) {
		fprintf(stderr, "%s: failed to parse file info\n", __func__);
		goto out;
	}

	ret = sprintf(token, "#%d:a0=%s", SYSNO(statfs), file_header);
	token[ret] = '\0';

	ret = 0;

out:
	return ret;
}

int newfstatat_rt_parse(int mem_fd, __u64 *args, char *token)
{
	int ret = 0;
	__u64 dirfd = args[0];
	__u64 addr = args[1];
	char file_header[FILE_HEADER_LEN] = { 0 };

	ret = _file_info_parse(mem_fd, addr, NULL, file_header);
	if (ret) {
		fprintf(stderr, "%s: failed to parse file info\n", __func__);
		goto out;
	}

	/* a0: process AT_FDCWD */
	char A0[64] = { 0 };
	formalize_fd_str(dirfd, A0);

	ret = sprintf(token, "#%d:a0=%s:a1=%s", SYSNO(newfstatat), A0, file_header);
	token[ret] = '\0';

	ret = 0;

out:
	return ret;
}

int readlinkat_rt_parse(int mem_fd, __u64 *args, char *token)
{
	int ret = 0;
	__u64 dirfd = args[0];
	__u64 addr = args[1];
	__u64 bufsize = args[3];
	char file_header[FILE_HEADER_LEN] = { 0 };

	ret = _file_info_parse(mem_fd, addr, NULL, file_header);
	if (ret) {
		fprintf(stderr, "%s: failed to parse file info\n", __func__);
		goto out;
	}

	/* a0: process AT_FDCWD */
	char A0[64] = { 0 };
	formalize_fd_str(dirfd, A0);

	ret = sprintf(token, "#%d:a0=%s:a1=%s:a3=%llx", SYSNO(readlinkat),
		A0, file_header, bufsize);
	token[ret] = '\0';

	ret = 0;

out:
	return ret;
}

static int _rt_saddr_encode(int mem_fd, __u64 addr, __u64 addrlen, char **buf)
{
	int ret = 0;
	char *saddr = NULL;

	if (!addrlen) {
		char *null_str = strdup(NULL_STR);
		if (!null_str) {
			fprintf(stderr, "%s: strdup failed\n", __func__);
			ret = -1;
			goto out;
		}
		*buf = null_str;
		goto out;
	}

	ret = lseek(mem_fd, addr, SEEK_SET);
	if (ret == -1) {
		fprintf(stderr, "%s: Failed to access addr %llx: %s\n",
			__func__, addr, strerror(errno));
		goto out;
	}

	saddr = calloc(addrlen, sizeof(char));
	if (!saddr) {
		fprintf(stderr, "%s: Failed to calloc: %s\n", __func__, strerror(errno));
		goto out;
	}

	ret = read(mem_fd, saddr, addrlen);
	if (ret == -1) {
		fprintf(stderr, "%s: Failed to read from %llx: %s\n",
			__func__, addr, strerror(errno));
		goto out;
	}

	ret = encode_saddr_struct(saddr, addrlen, buf);
	if (ret) {
		fprintf(stderr, "%s: failed to encode sockaddr\n", __func__);
		goto out;
	}

	ret = 0;

out:
	if (saddr) free(saddr);

	return ret;
}

int connect_rt_parse(int mem_fd, __u64 *args, char *token)
{
	int ret = 0;
	__u64 addr = args[1];
	__u64 addrlen = args[2];
	char *saddr_encode = NULL;

	ret = _rt_saddr_encode(mem_fd, addr, addrlen, &saddr_encode);
	if (ret) {
		fprintf(stderr, "%s: failed to encode saddr\n", __func__);
		goto out;
	}

	ret = sprintf(token, "#%d:a1=%s:a2=%llx", SYSNO(connect),
				saddr_encode, addrlen);
	token[ret] = '\0';

	ret = 0;

out:
	free(saddr_encode);
	return ret;
}

int bind_rt_parse(int mem_fd, __u64 *args, char *token)
{
	int ret = 0;
	__u64 addr = args[1];
	__u64 addrlen = args[2];
	char *saddr_encode = NULL;

	ret = _rt_saddr_encode(mem_fd, addr, addrlen, &saddr_encode);
	if (ret) {
		fprintf(stderr, "%s: failed to encode saddr\n", __func__);
		goto out;
	}

	ret = sprintf(token, "#%d:a1=%s:a2=%llx", SYSNO(bind),
				saddr_encode, addrlen);
	token[ret] = '\0';

	ret = 0;

out:
	free(saddr_encode);
	return ret;
}

/*
int accept_rt_parse(int mem_fd, __u64 *args, char *token)
{
	int ret = 0;
	__u64 addr = args[1];
	__u64 addrlen = sizeof(struct sockaddr_storage);
	char *saddr_encode = NULL;

	ret = _rt_saddr_encode(mem_fd, addr, addrlen, &saddr_encode);
	if (ret) {
		fprintf(stderr, "%s: failed to encode saddr\n", __func__);
		goto out;
	}

	ret = sprintf(token, "#%d:a1=%s:a2=%llx", SYSNO(accept),
				saddr_encode, addrlen);
	token[ret] = '\0';

	ret = 0;

out:
	free(saddr_encode);
	return ret;
}

//	accept/accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags)
//	NOTE:
//	*addr only will be filled after the syscall is executed
//	*addrlen is initialized to the size of the structure pointed to by addr;
//		on return it will contain the actual size of the peer address
int accept4_rt_parse(int mem_fd, __u64 *args, char *token)
{
	int ret = 0;
	__u64 addr = args[1];
	__u64 addrlen = 16;
	__u64 flags = args[3];
	char *saddr_encode = NULL;

	ret = _rt_saddr_encode(mem_fd, addr, addrlen, &saddr_encode);
	if (ret) {
		fprintf(stderr, "%s: failed to encode saddr\n", __func__);
		goto out;
	}

	ret = sprintf(token, "#%d:a1=%s:a2=%llx:a3=%llx", SYSNO(accept4),
				saddr_encode, addrlen, flags);
	token[ret] = '\0';

	ret = 0;

out:
	free(saddr_encode);
	return ret;
}
*/

int recvmsg_rt_parse(int mem_fd, __u64 *args, char *token)
{
	int ret = 0;
	__u64 addr = args[1];
	__u64 flags = args[2];
	char *saddr = NULL;
	char *saddr_encode = NULL;

	ret = lseek(mem_fd, addr, SEEK_SET);
	if (ret == -1) {
		fprintf(stderr, "%s: Failed to access addr %llx: %s\n",
			__func__, addr, strerror(errno));
		goto out;
	}

	/* read msg_name from msghdr */
	__u64 msg_name_addr = 0, msg_namelen = 0;
	struct msghdr tmp_hdr = { 0 };
	size_t storage_size = sizeof(struct sockaddr_storage);

	ret = read(mem_fd, (char *)&tmp_hdr, sizeof(struct msghdr));
	if (ret == -1) {
		fprintf(stderr, "%s: Failed to read from %llx: %s\n",
			__func__, args[1], strerror(errno));
		goto out;
	}
	msg_name_addr = (__u64)tmp_hdr.msg_name;
	msg_namelen = (tmp_hdr.msg_namelen > storage_size) ?
			storage_size : tmp_hdr.msg_namelen;

	/* if msg_namelen is 0, msg_name is NULL */
	if (!msg_namelen) {
		saddr_encode = strdup(NULL_STR);
		if (!saddr_encode) {
			fprintf(stderr, "%s: strdup failed\n", __func__);
			ret = -1;
			goto out;
		}
	} else {
		saddr = malloc(msg_namelen);
		if (!saddr) {
			fprintf(stderr, "%s: Failed to malloc: %s\n",
				__func__, strerror(errno));
			goto out;
		}
		memset(saddr, 0, msg_namelen);

		ret = lseek(mem_fd, msg_name_addr, SEEK_SET);
		if (ret == -1) {
			fprintf(stderr, "%s: Failed to access addr %llx: %s\n",
				__func__, addr, strerror(errno));
			goto out;
		}
		
		ret = read(mem_fd, saddr, msg_namelen);
		if (ret == -1) {
			fprintf(stderr, "%s: Failed to read from %llx: %s\n",
				__func__, args[1], strerror(errno));
			goto out;
		}

		ret = encode_saddr_struct(saddr, msg_namelen, &saddr_encode);
		if (ret) {
			fprintf(stderr, "%s: failed to encode sockaddr\n", __func__);
			goto out;
		}
	}

	ret = sprintf(token, "#%d:a1=%s:a2=%llx", SYSNO(recvmsg), saddr_encode, flags);
	token[ret] = '\0';

	ret = 0;

out:
	if (saddr_encode) free(saddr_encode);
	if (saddr) free(saddr);

	return ret;
}

int sendmmsg_rt_parse(int mem_fd, __u64 *args, char *token)
{
	int ret = 0;
	__u64 addr = args[1];
//	__u64 num_msg = args[2]; 
	int num_msg = 1; // TODO: only check 1 for experiments
	__u64 flags = args[3];
	char *saddr = NULL;
	char *saddr_encode = NULL;

	ret = lseek(mem_fd, addr, SEEK_SET);
	if (ret == -1) {
		fprintf(stderr, "%s: Failed to access addr %llx: %s\n",
			__func__, addr, strerror(errno));
		goto out;
	}

	struct mmsghdr *msgvec = calloc(num_msg, sizeof(struct mmsghdr));
	if (!msgvec) {
		fprintf(stderr, "%s: calloc failed %s\n", __func__, strerror(errno));
		ret = -1;
		goto out;
	}

	ret = read(mem_fd, (char *)msgvec, sizeof(struct mmsghdr) * num_msg);
	if (ret == -1) {
		fprintf(stderr, "%s: Failed to read from %llx: %s\n",
			__func__, addr, strerror(errno));
		goto out;
	}

	size_t storage_size = sizeof(struct sockaddr_storage);
	/* maximum size of buf to accomodate sockaddr */
	saddr = calloc(1, storage_size);
	if (!saddr) {
		fprintf(stderr, "%s: Failed to malloc: %s\n", __func__, strerror(errno));
		goto out;
	}

	/* currently only encode one hdr because of profiling */
//	for (i = 0; i < num_msg; i++) {
		/* read msg_name from msghdr */
	struct mmsghdr *cur_hdr = msgvec;
	struct msghdr *msg_hdr = &cur_hdr->msg_hdr;

	__u64 msg_name_addr = (__u64)msg_hdr->msg_name;
	__u64 msg_namelen = (msg_hdr->msg_namelen > storage_size) ?
				storage_size : msg_hdr->msg_namelen;

	if (!msg_namelen) {
		saddr_encode = strdup(NULL_STR);
		if (!saddr_encode) {
			fprintf(stderr, "%s: strdup failed\n", __func__);
			ret = -1;
			goto out;
		}
	}
	else {
		ret = lseek(mem_fd, msg_name_addr, SEEK_SET);
		if (ret == -1) {
			fprintf(stderr, "%s: Failed to access addr %llx: %s\n",
				__func__, msg_name_addr, strerror(errno));
			goto out;
		}
		
		memset(saddr, 0, storage_size);
	
		ret = read(mem_fd, saddr, msg_namelen);
		if (ret == -1) {
			fprintf(stderr, "%s: Failed to read from %llx: %s\n",
				__func__, args[1], strerror(errno));
			goto out;
		}
	
		ret = encode_saddr_struct(saddr, msg_namelen, &saddr_encode);
		if (ret) {
			fprintf(stderr, "%s: failed to encode sockaddr\n", __func__);
			goto out;
		}
	}

	ret = sprintf(token, "#%d:a1=%s:a3=%llx", SYSNO(sendmmsg), saddr_encode, flags);
	token[ret] = '\0';

	ret = 0;

out:
	if (saddr_encode) free(saddr_encode);
	if (saddr) free(saddr);

	return ret;
}

int sendto_rt_parse(int mem_fd, __u64 *args, char *token)
{
	int ret = 0;
	__u64 flags = args[3];
	__u64 addr = args[4];
	__u64 addrlen = args[5];

	char *saddr_encode = NULL;

	ret = _rt_saddr_encode(mem_fd, addr, addrlen, &saddr_encode);
	if (ret) {
		fprintf(stderr, "%s: failed to encode saddr\n", __func__);
		goto out;
	}

	ret = sprintf(token, "#%d:a3=%llx:a4=%s", SYSNO(sendto),
		flags, saddr_encode);
	token[ret] = '\0';

	ret = 0;

out:
	free(saddr_encode);
	return ret;
}

// DEBUG
/*
int ioctl_rt_parse(int mem_fd, __u64 *args, char *token)
{
	int ret = 0;
	__u64 op = args[1];

	ret = sprintf(token, "#%d:a1=%llx", SYSNO(ioctl), op);
	token[ret] = '\0';

	return 0;
}
int futex_rt_parse(int mem_fd, __u64 *args, char *token)
{
	int ret = 0;
	__u64 op = args[1];

	ret = sprintf(token, "#%d:a1=%llx", SYSNO(futex), op);
	token[ret] = '\0';

	return 0;
}
*/
