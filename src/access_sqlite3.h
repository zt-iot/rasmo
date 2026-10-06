#ifndef _ACCESS_SQLITE3_H_
#define _ACCESS_SQLITE3_H_

#include <sqlite3.h>
#include "access_control.h"

int init_sqlite_db(const char *, const char *, sqlite3 **);
void finalize_sqlite_db(sqlite3 *db);
int sync_ip_db(sqlite3 *db, const char *table_name, const char *xid, struct ip_batch *arr, int num);
int commit_ip_db(sqlite3 *db, const char *table_name, struct ip_batch *arr, int num);
int new_record_db(sqlite3 *db, const char *table_name, struct ip_batch *arr, int num);
int query_xid_db(sqlite3 *db, char *xid, int bufsize);
int query_unsync_db(sqlite3 *db, const char *table_name, struct ip_batch **ip_arr, int *pnum);
int query_unblocked_db(sqlite3 *db, const char *table_name, struct ip_batch **ip_arr, int *pnum);
int query_blocked_db(sqlite3 *db, const char *table_name, struct ip_batch **ip_arr, int *pnum);
int query_recov_db(sqlite3 *db, const char *table_name, struct ip_batch **ip_arr, int *pnum);
int query_resend_db(sqlite3 *db, const char *table_name, struct ip_batch **ip_arr, int *pnum);
int query_uncmt_db(sqlite3 *db, const char *table_name, struct ip_batch **ip_arr, int *pnum);

#endif

