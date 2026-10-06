#ifndef _SECCOMP_JSON_H_
#define _SECCOMP_JSON_H_

#include <stdint.h>

int generate_json_profile(char *, char *, char *, void *, int);
int load_json_profile(char *, uint32_t *, void **, int *);

#endif
