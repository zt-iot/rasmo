#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <ctype.h>
#include "rasmo_util.h"

const char hex_asc_upper[] = "0123456789ABCDEF";
#define hex_asc_upper_lo(x)	hex_asc_upper[((x) & 0x0f)]
#define hex_asc_upper_hi(x)	hex_asc_upper[((x) & 0xf0) >> 4]

char *hex_byte_pack_upper(char *buf, char byte)
{
	*buf++ = hex_asc_upper_hi(byte);
	*buf++ = hex_asc_upper_lo(byte);

	return buf;
}

// ipv4
int get_dyn_port_range(int *min, int *max)
{
	int ret = 0;
	int min_port, max_port;
	char *ipv4_port_range = "/proc/sys/net/ipv4/ip_local_port_range";
	FILE *fp = fopen(ipv4_port_range, "r");
	if (!fp) {
		fprintf(stderr, "%s: failed to open %s\n", __func__, ipv4_port_range);
		ret = -1;
		goto out;
	}

	if (fscanf(fp, "%d %d", &min_port, &max_port) != 2) {
		fprintf(stderr, "%s: failed to acquire dyn port range\n", __func__);
		ret = -1;
		goto out;
	}

	fclose(fp);

	if (min) *min = min_port;
	if (max) *max = max_port;

out:
	return ret;
}

int encode_exe_name(const char *path, char **hex_name)
{
	int ret = 0;
	char buf[PATH_MAX*2+1] = { 0 };
	char *p_buf = buf;
	const char *p = path;

	if (strlen(path) > PATH_MAX) {
		fprintf(stderr, "%s: path length beyond limit\n", __func__);
		ret = -1;
		goto out;
	}

	while (*p != '\0') {
		// skip "
		if (*p == '"') { p++; continue; }
		p_buf = hex_byte_pack_upper(p_buf, *p++);
	}

	*p_buf = '\0';

	*hex_name = strdup(buf);
	ret = 0;

out:
	if (ret) *hex_name = NULL;
	return ret;
}

static int dyn_list_len = 0;
static char (*dyn_path_list)[PATH_MAX] = NULL;

int init_dyn_path_list(char *list_path)
{
	int ret = 0, idx = 0;
	char *fn = (list_path)? list_path : "file_whitelist.conf";
	char tmp[PATH_MAX] = { 0 };

	FILE *fp = fopen(fn, "r");
	if (!fp && errno != ENOENT) {
		fprintf(stderr, "%s: failed to open file %s\n", __func__, fn);
		ret = -1;
		goto out;	
	}

	// get number of lines
	if (fp) {
		while ((fgets(tmp, PATH_MAX, fp))) {
			// # for comments
			if (tmp[0] == '#')
				continue;
			dyn_list_len++;
		}
		rewind(fp);
	}
	else {
		ret = 0;  goto out;	
	}

	if (!dyn_list_len) { ret = 0; goto out; }

	dyn_path_list = calloc(dyn_list_len, PATH_MAX * sizeof(char));
	if (!dyn_path_list) {
		fprintf(stderr, "%s: failed to allocate memory\n", __func__);
		ret = -1;
		goto out;
	}

	memset(tmp, 0, PATH_MAX);

	// read each line
	while (fgets(tmp, PATH_MAX, fp)) {
		tmp[strcspn(tmp, "\n")] = '\0';
		if (tmp[0] == '#' || tmp[0] == '\0') continue;

		memcpy(dyn_path_list[idx++], tmp, PATH_MAX);
	}

out:
	if (fp) fclose(fp);
	return ret;
}

void finalize_dyn_path_list(void)
{
	if (dyn_path_list) free(dyn_path_list);
}

static inline int check_dyn_path(char *path)
{
	int i, ret = 0;
	for (i = 0; i < dyn_list_len; i++) {
		size_t len = strlen(dyn_path_list[i]);

		if (!memcmp(path, dyn_path_list[i], len)) {
			ret = 1;
			break;
		}
	}

	return ret;
}

/* FIXME: mask dynamic part in the path
	check if the file exists or not;
	How to deal with the relative path & symlink?
*/
int process_path(char *fpath, char *final_path)
{
	char substr[128] = { 0 };
	char suffix[PATH_MAX] = { 0 };
	char path[PATH_MAX] = { 0 };
	int file_exist = 1;
	int len = 0;

	// empty filename: happens in libcamera-hello
	len = formalize_path(fpath, path);
	if (!len) {
		file_exist = 0;
		snprintf(path, PATH_MAX, "%s", NULL_STR);
		path[strlen(NULL_STR)] = '\0';
		goto out;
	}

	int dyn_path = check_dyn_path(path);
	if (dyn_path) {
		file_exist = 0;
		goto out;
	}

	/* detect /proc/{pid,self} dynamic files */
	sscanf(path, "/proc/%[^/]/%s", substr, suffix);
	if (strlen(substr) &&
		(!strcmp(substr, "self") || string_is_number(substr))) {
		snprintf(final_path, PATH_MAX, "/proc/<pid>/%s", suffix);
		file_exist = 0;

		return file_exist;
	}
	else {
		struct stat tmp_stat = { 0 };

		if (access(path, F_OK)) {
			file_exist = 0;
		}
		else if (lstat(path, &tmp_stat)) {
			file_exist = 0;
		}
		else if (!strncmp(path, ".", len) ||
				!strncmp(path, "..", len) ||
				S_ISLNK(tmp_stat.st_mode)) {
					file_exist = 0;
		}
	}

out:
	memcpy(final_path, path, strlen(path));
	final_path[strlen(path)] = '\0';

	return file_exist;
}

int resolve_abs_path(const char *path, char *output)
{
	int ret = 0;
	char *parse_path = NULL;

	if (!path || !output) {
		fprintf(stderr, "%s: invalid argument\n", __func__);
		ret = -1;
		goto out;
	}

	/* if relative path, resolve and go out */
	if (strchr(path, '/')) {
		if (!(realpath(path, output))) {
			fprintf(stderr, "Invalid binary path: %s\n", path);
			ret = -1;
		}
		goto out;
	}

	/* if not, search PATH */
	const char *path_env = getenv("PATH");
	if (!path_env) {
		path_env = "/usr/local/bin:/usr/bin:/bin";
	}
	parse_path = strdup(path_env);
	char *token = strtok(parse_path, ":");

	int found = 0;

	while (token) {
		char search_path[PATH_MAX] = { 0 };

		/* path longer than the limit, incorrect */
		if (snprintf(search_path, PATH_MAX, "%s/%s", token, path) >= PATH_MAX) {
			token = strtok(NULL, ":");
			continue;
		}

		/* found */
		if (!access(search_path, X_OK)) {
			if (!(realpath(search_path, output))) {
				fprintf(stderr, "Invalid binary path: %s\n", search_path);
				ret = -1;
			}
			found = 1;
			break;
		}

		token = strtok(NULL, ":");
	}

	ret = (found)? 0 : -1;

out:
	free(parse_path);

	return ret;
}
