#ifndef _HMAP_H_
#define _HMAP_H_

/* zero: equal; non-zero: not equal */
typedef int (*compare_fn_t)(void *elem, char *key);

struct hash_node {
	unsigned int hash;
	void *element;
	struct hash_node *next;
	struct hash_node *prev;
};

struct bucket {
	struct hash_node *head;
};

struct hmap {
	unsigned int seed;
	struct bucket *buckets;
	int num_buckets; /* roundup power of two */
	compare_fn_t compare_fn; /* key comparison function */
};

int hmap_alloc(unsigned long, compare_fn_t, struct hmap **);
int hmap_add_elem(void *, char *, struct hmap *);
int hmap_lookup_elem(char *, struct hmap *, void **out);
int hmap_delete_elem(char *, struct hmap *);
void hmap_finalize(struct hmap *);
int load_hmap_from_file(char *path, struct hmap **pmap);

#endif
