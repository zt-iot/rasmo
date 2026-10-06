#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "access_sqlite3.h"


#if 0
static int table_exist(sqlite3 *db, const char *table_name)
{
	int ret = 0, exist = 0;
	sqlite3_stmt *stmt = NULL;

	/* select from sqlite_master and check if table exists */
	char *sql = 
		"SELECT * FROM sqlite_master WHERE "
		"type = 'table' AND name = ?1;";

	if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
		fprintf(stderr, "%s: compile failed (%s)\n", __func__, sqlite3_errmsg(db));
		return -1;
	}

	if (sqlite3_bind_text(stmt, 1, table_name, -1, SQLITE_TRANSIENT) != SQLITE_OK) {
		fprintf(stderr, "%s: bind text failed (%s)\n", __func__, sqlite3_errmsg(db));
		sqlite3_finalize(stmt);
		return -1;
	}

	ret = sqlite3_step(stmt);
	if (ret == SQLITE_ROW) {
		exist = 1;
	}
	else if (ret == SQLITE_DONE) {
		exist = 0;
	}
	else {
		exist = -1;
	}

	sqlite3_finalize(stmt);

	return exist;
}
#endif

/* create DB connection and create table if not exist */
int init_sqlite_db(const char *db_name, const char *table_name, sqlite3 **ppdb)
{
	int ret = 0;
	sqlite3 *db = NULL;

	char *sql = sqlite3_mprintf(
			"CREATE TABLE IF NOT EXISTS \"%w\" ("
			"ip TEXT PRIMARY KEY NOT NULL,"
			"committed BOOLEAN NOT NULL DEFAULT FALSE,"
			"sync BOOLEAN NOT NULL DEFAULT FALSE,"
			"unblocked BOOLEAN NOT NULL DEFAULT FALSE);"
			" "
			"CREATE TABLE IF NOT EXISTS kv ("
			"key TEXT PRIMARY KEY NOT NULL, "
			"value TEXT NOT NULL);"
			" "
			"INSERT INTO kv(key, value) "
			"VALUES ('xid', '0')"
			"ON CONFLICT (key) DO NOTHING;", table_name);
	if (!sql) {
		fprintf(stderr, "%s: sql allocation failed\n", __func__);
		ret = -1;
		goto out;
	}

	/* open db connection */
	if (sqlite3_open(db_name, &db) != SQLITE_OK) {
		fprintf(stderr, "Failed to open DB; error: %s\n", sqlite3_errmsg(db));
		ret = -1;
		goto out;
	}

	sqlite3_busy_timeout(db, 5000);                       /* per connection */
	sqlite3_exec(db, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);
	sqlite3_exec(db, "PRAGMA synchronous=FULL;", NULL, NULL, NULL);	

	if (sqlite3_exec(db, sql, NULL, NULL, NULL) != SQLITE_OK) {
		fprintf(stderr, "%s: Failed create table (%s)\n",
				__func__, sqlite3_errmsg(db));
		ret = -1;
		goto out;
	}

	ret = 0;
	*ppdb = db;

out:
	if (ret) sqlite3_close(db);
	sqlite3_free(sql);
	return ret;
}

void finalize_sqlite_db(sqlite3 *db)
{
	sqlite3_close(db);
}

int new_record_db(sqlite3 *db, const char *table_name, struct ip_batch *arr, int num)
{
	int ret = 0, i;
	sqlite3_stmt *stmt = NULL;

	/* do nothing if no data */
	if (!arr || !num) return 0;

	/* mprintf for identifer and set values using sqlite3_bind_*() calls 
		more secure */
	char *sql = sqlite3_mprintf(
		"INSERT INTO \"%w\" (ip, committed, sync, unblocked) "
		"VALUES (?, FALSE, FALSE, FALSE) ON CONFLICT (ip) DO UPDATE "
		"SET committed = EXCLUDED.committed, "
		"sync = EXCLUDED.sync, "
		"unblocked = EXCLUDED.unblocked;", table_name);
	if (!sql) {
		fprintf(stderr, "%s: sql allocation failed (%s)\n", __func__, sqlite3_errmsg(db));
		ret = -1;
		goto out;
	}

	if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
		fprintf(stderr, "%s: prepare failed with error %s\n", __func__, sqlite3_errmsg(db));
		ret = -1;
		goto out;
	}

	/* transaction begin */
	if (sqlite3_exec(db, "BEGIN IMMEDIATE;", NULL, NULL, NULL) != SQLITE_OK) {
		fprintf(stderr, "%s: Failed to start a transaction (%s)\n",
				__func__, sqlite3_errmsg(db));
		ret = -1;
		goto out;
	}

	for (i = 0; i < num; i++) {
		struct ip_batch *cur = &arr[i];
		char *ip = cur->ip_addr;

		if (sqlite3_bind_text(stmt, 1, ip, -1, SQLITE_STATIC) != SQLITE_OK) {
			fprintf(stderr, "%s: bind failed (%s)\n", __func__, sqlite3_errmsg(db));
			ret = -1;
			goto rb;
		}
	
		if (sqlite3_step(stmt) != SQLITE_DONE) {
			fprintf(stderr, "%s: execution failed (%s)\n", __func__, sqlite3_errmsg(db));
			ret = -1;
			goto rb;
		}

		if (sqlite3_reset(stmt) != SQLITE_OK) {
			fprintf(stderr, "%s: reset got a problem (%s)\n", __func__, sqlite3_errmsg(db));
			ret = -1;
			goto rb;
		}
	}

	/* transaction commit */
	if (sqlite3_exec(db, "COMMIT;", NULL, NULL, NULL) != SQLITE_OK) {
		fprintf(stderr, "%s: Failed to commit a transaction (%s)\n",
				__func__, sqlite3_errmsg(db));
		ret = -1;
		goto rb;
	}
	
	ret = 0;

rb:
	/* rollback if error */
	if (ret == -1) sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
out:
	sqlite3_finalize(stmt);
	sqlite3_free(sql);
	return ret;
}

int commit_ip_db(sqlite3 *db, const char *table_name, struct ip_batch *arr, int num)
{
	int ret = 0, i;
	sqlite3_stmt *stmt = NULL;

	/* do nothing if no data */
	if (!arr || !num) return 0;

	/* %w is only for SQL identifiers */
	char *sql = sqlite3_mprintf(
		"UPDATE \"%w\" "
		"SET committed = TRUE "
		"WHERE ip = ?;", table_name);
	if (!sql) {
		fprintf(stderr, "%s: sql allocation failed (%s)\n", __func__, sqlite3_errmsg(db));
		ret = -1;
		goto out;
	}

	if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
		fprintf(stderr, "%s: prepare failed with error %s\n", __func__, sqlite3_errmsg(db));
		ret = -1;
		goto out;
	}

	/* transaction begin */
	if (sqlite3_exec(db, "BEGIN IMMEDIATE;", NULL, NULL, NULL) != SQLITE_OK) {
		fprintf(stderr, "%s: Failed to start a transaction (%s)\n",
				__func__, sqlite3_errmsg(db));
		ret = -1;
		goto out;
	}

	for (i = 0; i < num; i++) {
		struct ip_batch *cur = &arr[i];
		char *ip = cur->ip_addr;

		if (sqlite3_bind_text(stmt, 1, ip, -1, SQLITE_STATIC) != SQLITE_OK) {
			fprintf(stderr, "%s: bind IP failed (%s)\n", __func__, sqlite3_errmsg(db));
			ret = -1;
			goto rb;
		}

		if (sqlite3_step(stmt) != SQLITE_DONE) {
			fprintf(stderr, "%s: execution failed (%s)\n", __func__, sqlite3_errmsg(db));
			ret = -1;
			goto rb;
		}

		if (sqlite3_reset(stmt) != SQLITE_OK) {
			fprintf(stderr, "%s: reset got a problem (%s)\n", __func__, sqlite3_errmsg(db));
			ret = -1;
			goto rb;
		}
	}

	if (sqlite3_exec(db, "COMMIT;", NULL, NULL, NULL) != SQLITE_OK) {
		fprintf(stderr, "%s: Failed to commit a transaction (%s)\n",
				__func__, sqlite3_errmsg(db));
		ret = -1;
		goto rb;
	}
	
	ret = 0;

rb:
	/* rollback if error */
	if (ret == -1) sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);

out:
	sqlite3_finalize(stmt);
	sqlite3_free(sql);
	return ret;
}

/* called after netfilter transaction */
int sync_ip_db(sqlite3 *db, const char *table_name, const char *xid, struct ip_batch *arr, int num)
{
	int ret = 0, i;
	sqlite3_stmt *stmt = NULL;
	sqlite3_stmt *stmt_kv = NULL;

	/* do nothing if no data */
	if (!arr || !num) return 0;
	/* reject if xid has more than 20 digits for a 64-bit uint */
	if (strlen(xid) > 20) {
		fprintf(stderr, "%s: Invalid xid\n", __func__);
		return -1;
	}	

	char *sql = sqlite3_mprintf(
		"INSERT INTO \"%w\" (ip, committed, sync, unblocked)"
		"VALUES (?, TRUE, TRUE, ?) "
		"ON CONFLICT (ip) DO "
		"UPDATE SET "
		"committed = EXCLUDED.committed, "
		"sync = EXCLUDED.sync, "
		"unblocked = EXCLUDED.unblocked;", table_name);
	if (!sql) {
		fprintf(stderr, "%s: sql allocation failed (%s)\n", __func__, sqlite3_errmsg(db));
		ret = -1;
		goto out;
	}
	char *sql_kv = "UPDATE kv SET value = ? WHERE key = 'xid';";

	/* complie the SQL statement */
	if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
		fprintf(stderr, "%s: prepare sync sql failed (%s)\n", __func__, sqlite3_errmsg(db));
		ret = -1;
		goto out;
	}

	if (sqlite3_prepare_v2(db, sql_kv, -1, &stmt_kv, NULL) != SQLITE_OK) {
		fprintf(stderr, "%s: prepare kv failed (%s)\n", __func__, sqlite3_errmsg(db));
		ret = -1;
		goto out;
	}

	if (sqlite3_bind_text(stmt_kv, 1, xid, -1, SQLITE_STATIC) != SQLITE_OK) {
		fprintf(stderr, "%s: bind xid failed (%s)\n", __func__, sqlite3_errmsg(db));
		ret = -1;
		goto out;
	}

	/* transaction begin */
	if (sqlite3_exec(db, "BEGIN IMMEDIATE;", NULL, NULL, NULL) != SQLITE_OK) {
		fprintf(stderr, "%s: Failed to start a transaction (%s)\n",
				__func__, sqlite3_errmsg(db));
		ret = -1;
		goto out;
	}

	/* execute sql */
	for (i = 0; i < num; i++) {
		struct ip_batch *cur = &arr[i];
		int op = cur->op;
		char *ip = cur->ip_addr;

		if (sqlite3_bind_text(stmt, 1, ip, -1, SQLITE_STATIC) != SQLITE_OK) {
			fprintf(stderr, "%s: bind IP failed (%s)\n", __func__, sqlite3_errmsg(db));
			ret = -1;
			goto rb;
		}

		if (sqlite3_bind_int(stmt, 2, op) != SQLITE_OK) {
			fprintf(stderr, "%s: bind OP failed (%s)\n", __func__, sqlite3_errmsg(db));
			ret = -1;
			goto rb;
		}

		if (sqlite3_step(stmt) != SQLITE_DONE) {
			fprintf(stderr, "%s: execution failed (%s)\n", __func__, sqlite3_errmsg(db));
			ret = -1;
			goto rb;
		}

		/* reset does not change the values of bindings on the prepared statement */
		if (sqlite3_reset(stmt) != SQLITE_OK) {
			fprintf(stderr, "%s: reset got a problem (%s)\n", __func__, sqlite3_errmsg(db));
			ret = -1;
			goto rb;
		}
	}

	/* update kv store */
	if (sqlite3_step(stmt_kv) != SQLITE_DONE) {
		fprintf(stderr, "%s: update kv failed (%s)\n", __func__, sqlite3_errmsg(db));
		ret = -1;
		goto rb;
	}

	/* transaction commit */
	if (sqlite3_exec(db, "COMMIT;", NULL, NULL, NULL) != SQLITE_OK) {
		fprintf(stderr, "%s: Failed to commit a transaction (%s)\n",
				__func__, sqlite3_errmsg(db));
		ret = -1;
		goto rb;
	}
	
	ret = 0;

rb:
	/* rollback if error */
	if (ret == -1) sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);

out:
	sqlite3_finalize(stmt);
	sqlite3_finalize(stmt_kv);
	sqlite3_free(sql);
	return ret;
}

enum filter {
	UNCOMMITTED = 0,
	UNSYNC,
	BLOCKED,
	BLOCKED_UNSYNC,
	BLOCKED_RECOV,
	UNBLOCKED,
	NUM_FILTER
};

static char *filters[] = {
	[UNCOMMITTED] = "committed = FALSE",
	[UNSYNC] = "sync = FALSE",
	[BLOCKED] = "committed = TRUE AND unblocked = FALSE",
	[BLOCKED_UNSYNC] = "sync = FALSE AND unblocked = FALSE",
	[BLOCKED_RECOV] = "unblocked = FALSE",
	[UNBLOCKED] = "unblocked = TRUE"
};

static int query_batch(sqlite3 *db, const char *table_name, int f_idx, struct ip_batch **ip_arr, int *pnum)
{
	int ret = 0;
	size_t num = 512;
	sqlite3_stmt *stmt = NULL;
	size_t total_num = 0;

	if (f_idx >= NUM_FILTER) {
		fprintf(stderr, "Unsupported filter\n");
		return -1;
	}

	char *sql = sqlite3_mprintf(
		"SELECT ip, unblocked FROM \"%w\" "
		"WHERE %s;", table_name, filters[f_idx]);
	if (!sql) {
		fprintf(stderr, "%s: sql allocation failed (%s)\n", __func__, sqlite3_errmsg(db));
		ret = -1;
		goto out;
	}

	if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
		fprintf(stderr, "%s: prepare sync sql failed (%s)\n", __func__, sqlite3_errmsg(db));
		ret = -1;
		goto out;
	}

	/* init realloc if needed */
	struct ip_batch *batch = calloc(num, sizeof(struct ip_batch));
	if (!batch) {
		fprintf(stderr, "%s: batch allocation failed\n", __func__);
		ret = -1;
		goto out;
	}
	
	/* retrieve result */
	while ((ret = sqlite3_step(stmt)) == SQLITE_ROW) {
		/* increase buf size if full */
		if (total_num == num) {
			num *= 2;
			struct ip_batch *tmp = realloc(batch, sizeof(struct ip_batch) * num);
			if (!tmp) {
				fprintf(stderr, "Failed to realloc\n");
				ret = -1;
				free(batch);
				goto out;
			}
			batch = tmp;
		}

		/* copy the data into the array */
		struct ip_batch *cur = &batch[total_num++];
		const unsigned char *ip = sqlite3_column_text(stmt, 0);
		int op = sqlite3_column_int(stmt, 1);

		cur->op = op;
		snprintf(cur->ip_addr, IP_ADDR_LEN, "%s", ip);
	}

	if (ret != SQLITE_DONE) {
		fprintf(stderr, "%s: query data failed (%s)\n", __func__, sqlite3_errmsg(db));
		ret = -1;
		free(batch);
		goto out;
	}

	/* if no required entries, return */
	if (!total_num) {
		free(batch); *ip_arr = NULL;
		*pnum = 0; ret = 0;
		goto out;
	}

	/* if data, realloc */
	struct ip_batch *tmp = realloc(batch, sizeof(struct ip_batch) * total_num);
	if (!tmp) {
		fprintf(stderr, "Failed to realloc\n");
		ret = -1;
		free(batch);
		goto out;
	}
	*ip_arr = tmp;
	*pnum = total_num;
	ret = 0;

out:
	sqlite3_finalize(stmt);
	sqlite3_free(sql);
	return ret;
}

/* user should manage the lifetime of *ip_arr */
int query_unsync_db(sqlite3 *db, const char *table_name, struct ip_batch **ip_arr, int *pnum)
{
	return query_batch(db, table_name, UNSYNC, ip_arr, pnum);
}

int query_uncmt_db(sqlite3 *db, const char *table_name, struct ip_batch **ip_arr, int *pnum)
{
	return query_batch(db, table_name, UNCOMMITTED, ip_arr, pnum);
}

int query_blocked_db(sqlite3 *db, const char *table_name, struct ip_batch **ip_arr, int *pnum)
{
	return query_batch(db, table_name, BLOCKED, ip_arr, pnum);
}

int query_recov_db(sqlite3 *db, const char *table_name, struct ip_batch **ip_arr, int *pnum)
{
	return query_batch(db, table_name, BLOCKED_RECOV, ip_arr, pnum);
}

int query_resend_db(sqlite3 *db, const char *table_name, struct ip_batch **ip_arr, int *pnum)
{
	return query_batch(db, table_name, BLOCKED_UNSYNC, ip_arr, pnum);
}

int query_unblocked_db(sqlite3 *db, const char *table_name, struct ip_batch **ip_arr, int *pnum)
{
	return query_batch(db, table_name, UNBLOCKED, ip_arr, pnum);
}

/* user manage xid buffer lifetime */
int query_xid_db(sqlite3 *db, char *xid, int bufsize)
{
	int ret = 0;
	char *sql = "SELECT value FROM kv WHERE key = 'xid'";
	sqlite3_stmt *stmt = NULL;

	if (!xid) {
		fprintf(stderr, "%s: Invalid parameter\n", __func__);
		ret = -1;
		goto out;
	}

	if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
		fprintf(stderr, "%s: prepare sql failed (%s)\n", __func__, sqlite3_errmsg(db));
		ret = -1;
		goto out;
	}

	/* execute select statement; should be only one row */
	if (sqlite3_step(stmt) != SQLITE_ROW) {
		fprintf(stderr, "%s: kv no data returned (%s)\n", __func__, sqlite3_errmsg(db));
		ret = -1;
		goto out;
	}

	/* get select data */
	const unsigned char *db_value = sqlite3_column_text(stmt, 0);
	int value_len = sqlite3_column_bytes(stmt, 0);
	if (value_len >= bufsize) {
		fprintf(stderr, "%s: invalid xid value\n", __func__);
		ret = -1;
		goto out;
	}
	snprintf(xid, bufsize, "%s", db_value);

	if (sqlite3_step(stmt) != SQLITE_DONE) {
		fprintf(stderr, "%s: query kv store failed (%s)\n", __func__, sqlite3_errmsg(db));
		ret = -1;
		goto out;
	}

out:
	sqlite3_finalize(stmt);
	return ret;
}

#if 0
char *db_name = "locallog.db";
char *table_name = "local_log";

/* test */
int main(int argc, char **argv)
{
	int ret = 0;
	sqlite3 *db = NULL;

	ret = init_sqlite_db(db_name, table_name, &db);
	if (ret) {
		fprintf(stderr, "ERROR\n");
		goto out;
	}

	char *ips[3] = { "192.168.0.1", "192.168.0.2", "192.168.0.3"};
	struct ip_batch batch[3] = { 0 };
	int i;

	for (i = 0; i < 3; i++) {
		batch[i].op = (i%2)? OP_UNBLOCK : OP_BLOCK;
		snprintf(batch[i].ip_addr, IP_ADDR_LEN, "%s", ips[i]);
	}

	ret = new_record_db(db, table_name, batch, 3);
	if (ret) {
		fprintf(stderr, "ERROR\n");
		goto out;
	}
/*
	ret = commit_ip_db(db, table_name, batch, 3);
	if (ret) {
		fprintf(stderr, "ERROR\n");
		goto out;
	}

	ret = sync_ip_db(db, table_name, "2323", batch, 3);
	if (ret) {
		fprintf(stderr, "ERROR\n");
		goto out;
	}
*/
	char buf[512] = { 0 };
	ret = query_xid_db(db, buf);
	if (ret) {
		fprintf(stderr, "ERROR\n");
		goto out;
	}
	fprintf(stderr, "xid: %s\n", buf);

	struct ip_batch *result = NULL;
	int num_result = 0;
	ret = query_unsync_db(db, table_name, &result, &num_result);
	if (ret) {
		fprintf(stderr, "ERROR\n");
		goto out;
	}

	fprintf(stderr, "unsync:\n");
	for (i = 0; i < num_result; i++) {
		fprintf(stderr, "%s %d\n", result[i].ip_addr, result[i].op);
	}
	free(result);

	ret = query_uncmt_db(db, table_name, &result, &num_result);
	if (ret) {
		fprintf(stderr, "ERROR\n");
		goto out;
	}

	fprintf(stderr, "uncommitted:\n");
	for (i = 0; i < num_result; i++) {
		fprintf(stderr, "%s %d\n", result[i].ip_addr, result[i].op);
	}
	free(result);

	ret = query_blocked_db(db, table_name, &result, &num_result);
	if (ret) {
		fprintf(stderr, "ERROR\n");
		goto out;
	}

	fprintf(stderr, "blocked:\n");
	for (i = 0; i < num_result; i++) {
		fprintf(stderr, "%s %d\n", result[i].ip_addr, result[i].op);
	}
	free(result);

	ret = query_recov_db(db, table_name, &result, &num_result);
	if (ret) {
		fprintf(stderr, "ERROR\n");
		goto out;
	}

	fprintf(stderr, "recovery:\n");
	for (i = 0; i < num_result; i++) {
		fprintf(stderr, "%s %d\n", result[i].ip_addr, result[i].op);
	}
	free(result);

	ret = query_unblocked_db(db, table_name, &result, &num_result);
	if (ret) {
		fprintf(stderr, "ERROR\n");
		goto out;
	}

	fprintf(stderr, "unblocked:\n");
	for (i = 0; i < num_result; i++) {
		fprintf(stderr, "%s %d\n", result[i].ip_addr, result[i].op);
	}
	free(result);
	

out:
	if (db) finalize_sqlite_db(db);
	return ret;
}

#endif
