#ifndef _FILTER_RT_H_
#define _FILTER_RT_H_

#include <limits.h>
#include "rasmo_hashmap.h"

#define INITIAL_BUFFER_LEN 65536

struct rt_file_info {
	int exist;
	char inode[32];
	char device[32];
	char mode[32];
	char path[PATH_MAX];
};

struct rt_app_profile {
	char *app_path;
	char *app_path_hex;
	struct hmap *profile;
};

#endif
