#ifndef _ACCESS_PARSER_H_
#define _ACCESS_PARSER_H_

int init_regex_parser(void);
int extract_username(char *, char *, int);
int extract_fingerprint(char *, char *, int);
int extract_validuser(char *, char *, int);
int extract_ipaddr(char *, char *, int);

#endif
