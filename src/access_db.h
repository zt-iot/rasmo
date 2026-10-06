#ifndef _ACCESS_DB_H
#define _ACCESS_DB_H

int fingerprint_db_init(unsigned int s);
void fingerprint_db_destroy(void);
int fingerprint_query(char *fp);
int fingerprint_add(char *fp);
int fingerprint_delete(char *fp);

int failed_hm_init(void);
void failed_hm_destroy(void);
int failed_query(char *ip, void **atp);
int failed_add(char *ip, int maxretry, char *fingerprint);
int failed_delete(char *ip);
#endif
