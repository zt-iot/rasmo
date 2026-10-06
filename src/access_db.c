#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "rasmo_hashmap.h"
#include "access_control.h"

/* database for fingerpints that successfully logged in */
#define INIT_TABLE_SIZE 65536
#define INIT_FPDB_SIZE 16

/* number of valid users to each device is limited 
	so linear search should be acceptable
*/
struct fpdb {
	char fp[FINGERPRINT_LEN];
};
struct fpdb *fpdb = NULL;
unsigned int fpdb_size = 0;

int fingerprint_db_init(unsigned int s)
{
	int ret = 0;

	if (!s) {
		fpdb_size = INIT_FPDB_SIZE;
	}
	else {
		fpdb_size = s;
	}

	fpdb = calloc(fpdb_size, sizeof(struct fpdb));
	if (!fpdb) {
		fprintf(stderr, "Failed to alloc memory for fingerprint db: %s\n",
			strerror(errno));
		ret = -1;
		goto out;
	}

out:
	return ret;
}

void fingerprint_db_destroy(void)
{
	if (fpdb) free(fpdb);
}

static inline int fingerprint_search_slot(void)
{
	int ret = 0;
	unsigned int i = 0;

	for (i = 0; i < fpdb_size; i++) {
		struct fpdb *cur = &fpdb[i];
		if (cur->fp[0] == '\0') {
			ret = i;
			goto out;
		}
	}

	/* expand size if no slot */
	fpdb_size *= 2;
	struct fpdb *new_mem = NULL;

	new_mem = realloc(fpdb, fpdb_size * sizeof(struct fpdb));
	if (!new_mem) {
		fprintf(stderr, "Failed to realloc for fingerprint db: %s\n",
			strerror(errno));
		ret = -1;
		goto out;
	}
	memset(new_mem+i, 0, (fpdb_size/2) * sizeof(struct fpdb)); // must initialize the mem

	fpdb = new_mem;
	ret = i;

out:
	return ret;
}

/* return index if found, otherwise -1 */
int fingerprint_query(char *fp)
{
	unsigned int i = 0;
	for (i = 0; i < fpdb_size; i++) {
		if (!memcmp(fp, fpdb[i].fp, FINGERPRINT_LEN)) {
			return i;
		}
	}
	return -1;
}

int fingerprint_add(char *fp)
{
	int ret = 0;
	int idx = -1;

	/* add if not exist */
	if (fingerprint_query(fp) < 0) {
		idx = fingerprint_search_slot();
		if (idx < 0) {
			fprintf(stderr, "%s: not able to add %s\n", __func__, fp);
			ret = -1;
			goto out;		
		}
		memcpy(fpdb[idx].fp, fp, FINGERPRINT_LEN);
	}

out:
	return ret;
}

int fingerprint_delete(char *fp)
{
	int ret = 0;
	int idx = fingerprint_query(fp);

	if (idx < 0) {
		fprintf(stderr, "%s: fingerprint %s does not exist\n", __func__, fp);
		ret = -1;
		goto out;
	}
	else {
		memset(fpdb[idx].fp, 0, FINGERPRINT_LEN);
	}

out:
	return ret;
}

/* hash table for failed login attempts */
struct hmap *failed_db = NULL;

/* how to identify if the key belongs to the element */
static int compare_attempts(void *at, char *key) {
	struct access_attempt *attempt = (struct access_attempt *) at;

	return strcmp(attempt->ip_addr, key);
}

int failed_hm_init(void)
{
	int ret = hmap_alloc(INIT_TABLE_SIZE, compare_attempts, &failed_db);
	if (ret) {
		fprintf(stderr, "%s: Failed to init db\n", __func__);
		goto out;
	}

out:
	return ret;
}

/* each allocated attempts are also free'd */
void failed_hm_destroy(void)
{
	hmap_finalize(failed_db);
}

int failed_add(char *ip, int maxretry, char *fingerprint)
{
	int ret = 0;
	struct access_attempt *attempt = calloc(1, sizeof(struct access_attempt));
	if (!attempt) {
		fprintf(stderr, "Failed to alloc memory for new access attempt\n");
		ret = -1;
		goto out;
	}

	attempt->num_failed += 1;
	attempt->maxretry = maxretry;
	snprintf(attempt->ip_addr, IP_ADDR_LEN, "%s", ip);
	snprintf(attempt->fingerprint, FINGERPRINT_LEN, "%s", fingerprint);

	ret = hmap_add_elem(attempt, ip, failed_db);
	if (ret) {
		fprintf(stderr, "Failed to add %s into failed hashtable\n", ip);
		goto out;
	}

out:
	return ret;
}

/* return value:
	= 0 not found
	< 0 error
	> 0 found
*/
int failed_query(char *ip, void **atp)
{
	 return hmap_lookup_elem(ip, failed_db, atp);
}

int failed_delete(char *ip)
{
	return hmap_delete_elem(ip, failed_db);
}

