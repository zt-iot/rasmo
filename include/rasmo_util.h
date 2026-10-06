#ifndef _UTIL_H_
#define _UTIL_H_

int get_dyn_port_range(int *min, int *max);
int encode_exe_name(const char *path, char **hex_name);
int init_dyn_path_list(char *list_path);
void finalize_dyn_path_list(void);
int process_path(char *fpath, char *final_path);
int resolve_abs_path(const char *path, char *out);
char *hex_byte_pack_upper(char *buf, char byte);

#define NULL_STR "(null)"

#define FILE_HEADER_LEN ( PATH_MAX + 1024 )
#define _STRINGIZE(s) #s
#define STRINGIZE(s) _STRINGIZE(s)


#define remove_hex_prefix(str) ({\
	char tmp[64] = { 0 }; int i;\
	char *tmp_p = tmp;\
	for (i=0; str[i]!='\0'; i++) { tmp[i]=tolower(str[i]); }\
	tmp[i] = '\0';\
	if (tmp[0] == '0' && tmp[1] == 'x') tmp_p += 2;\
	strdup(tmp_p);\
})

#define find_last_char(str, len, chr) ({\
	int _l = (len); int i = _l - 1;\
	char *_s = (str); char _c = (chr); \
	for (; ((_s[i]) != _c) && (i >= 0); i--) continue;\
	i;\
})


#define string_is_number(str) ({\
	char *_st = str; int _r = 1; \
	while (*_st) {\
		if (!isdigit(*_st)) { _r = 0; break; }\
		_st++; }\
	_r;\
})

#define formalize_path(org_path, new_path) ({\
	int len = 0; char *_orgp = (org_path);\
	char *_newp = (new_path);\
	if (_orgp) {\
		char *st = _orgp; while (*st == '\"') st++;\
		while (*st != '\"' && *st != '\0') { _newp[len++] = *st++; }\
	}\
	_newp[len] = '\0';\
	len;\
})

#endif
