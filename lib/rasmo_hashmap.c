#include <stdio.h>
#include <xxhash.h>
#include <errno.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "rasmo_hashmap.h"

#define INIT_TABLE_SIZE 65536
/* linux kernel code */
#define BITS_PER_LONG 64
static unsigned long roundup_pow_of_two(unsigned long num)
{
	unsigned long n = num - 1;
	int tmp = 0;

	if (num == 0) return 0;
	else if (n == 0) {
		tmp = 1;
		goto out;
	}

	tmp = BITS_PER_LONG;

	/* find last set bit of the number */
	if (!(n & (~0ul << 32))) {
		tmp -= 32;
		n <<= 32;
	}
	if (!(n & (~0ul << (BITS_PER_LONG-16)))) {
		tmp -= 16;
		n <<= 16;
	}
	if (!(n & (~0ul << (BITS_PER_LONG-8)))) {
		tmp -= 8;
		n <<= 8;
	}
	if (!(n & (~0ul << (BITS_PER_LONG-4)))) {
		tmp -= 4;
		n <<= 4;
	}
	if (!(n & (~0ul << (BITS_PER_LONG-2)))) {
		tmp -= 2;
		n <<= 2;
	}
	if (!(n & (~0ul << (BITS_PER_LONG-1)))) {
		tmp -= 1;
	}

out:
	return 1ul << tmp;
}

static int seed_generater(uint32_t *seed)
{
	int ret = 0; uint32_t value = 0;
	char *urandom = "/dev/urandom";
	ssize_t num_bytes = 0;
	int fd = -1;

	fd = open(urandom, O_RDONLY);
	if (fd == -1) {
		ret = -1;
		perror("Failed to open urandom: ");
		goto out;
	}

	num_bytes = read(fd, &value, sizeof(value));
	if (num_bytes != sizeof(unsigned int)) {
		ret = -1;
		if (num_bytes == -1) {
			perror("Failed to read from urandom: ");
		}
		else {
			perror("Insufficient data read: ");
		}
		goto out;
	}

	*seed = value;	

out:
	if (fd != -1) close(fd);

	return ret;
}

/* return value:
	= 0 not found
	< 0 error
	> 0 found
*/
int hmap_lookup_elem(char *key, struct hmap *map, void **out)
{
	int ret = 0;

	if (map == NULL || key == NULL) {
		fprintf(stderr, "%s: Invalid argument\n", __func__);
		ret = -1;
		goto out;
	}

	unsigned int seed = map->seed;
	struct bucket *buckets = map->buckets;
	int num_buckets = map->num_buckets;

	/* identify bucket */
	unsigned int hash = XXH32(key, strlen(key), seed);
	struct hash_node *head = (&buckets[hash & (num_buckets - 1)])->head;

	while (head != NULL) {
		if (head->hash == hash && !map->compare_fn(head->element, key)) {
			if (out) {
				*out = head->element;
			}
			ret = 1;
			break;
		}
		head = head->next;
	}

out:
	return ret;
}

/* add element to the map, if key is NULL then element is the key */
int hmap_add_elem(void *element, char *key, struct hmap *map)
{
	int ret = 0;

	if (map == NULL || element == NULL) {
		fprintf(stderr, "%s: Invalid argument\n", __func__);
		ret = -1;
		goto out;
	}

	unsigned int seed = map->seed;
	struct bucket *buckets = map->buckets;
	int num_buckets = map->num_buckets;

	if (!key) key = element;

	/* check if element already exists; add if not */
	ret = hmap_lookup_elem(key, map, NULL);
	if (ret > 0) goto out;
	else if (ret < 0) {
		fprintf(stderr, "%s: key: %s lookup failed\n", __func__, key);
		goto out;
	}

	/* insert if not exist */
	unsigned int hash = XXH32(key, strlen(key), seed);
	struct bucket *b = &buckets[hash & (num_buckets - 1)];
	struct hash_node *head = b->head;

	/* allocate hash node */
	struct hash_node *node = calloc(1, sizeof(struct hash_node));
	if (!node) {
		fprintf(stderr, "Failed to allocate mem for the node\n");
		ret = -1;
		goto out;
	}
	node->hash = hash;
	node->element = element;

	/* add to the head of the list */
	if (head) {
		struct hash_node *next = head;
		next->prev = node;
		node->next = next;
		node->prev = NULL;
	}
	b->head = node;

out:
	return ret;
}

/* delete element from the map */
int hmap_delete_elem(char *key, struct hmap *map)
{
	int ret = 0;

	if (map == NULL || key == NULL) {
		fprintf(stderr, "%s: Invalid argument\n", __func__);
		ret = -1;
		goto out;
	}

	unsigned int seed = map->seed;
	struct bucket *buckets = map->buckets;
	int num_buckets = map->num_buckets;

	unsigned int hash = XXH32(key, strlen(key), seed);
	struct bucket *b = &buckets[hash & (num_buckets - 1)];
	struct hash_node *head = b->head;

	while (head != NULL) {
		if ((head->hash == hash) && !map->compare_fn(head->element, key)) {
			struct hash_node *next = head->next;
			struct hash_node *prev = head->prev;

			/* if first element in the chain */
			if (head == b->head) b->head = next;
			/* if next or prev is not NULL, chain the previous element and the next */
			if (next) next->prev = prev;
			if (prev) prev->next = next;

			free(head->element);
			free(head);

			break;
		}
		head = head->next;
	}

out:
	return ret;
}


static int default_compare(void *elem, char *key)
{
	return strcmp((char *)elem, key);
}

/* empty hash map */
int hmap_alloc(unsigned long num_elements, compare_fn_t compare_fn, struct hmap **map)
{
	int ret = 0;

	if (!map) {
		ret = -1;
		fprintf(stderr, "Invalid argument to %s\n", __func__);
		goto out;
	}

	if (!compare_fn) compare_fn = default_compare;

	/* default size if num is not specified */
	if (num_elements == 0) num_elements = INIT_TABLE_SIZE;

	unsigned long num_buckets = roundup_pow_of_two(num_elements);
	unsigned int seed = 0;
	struct hmap *new_map = NULL;

	struct bucket *buckets = calloc(num_buckets, sizeof(struct bucket));
	if (!buckets) {
		fprintf(stderr, "Failed to allocate memory for buckets\n");
		ret = -1;
		goto out;
	}

	ret = seed_generater(&seed);
	if (ret) {
		fprintf(stderr, "Failed to generate seed\n");
		goto out;
	}

	new_map = calloc(1, sizeof(struct hmap));
	if (!new_map) {
		fprintf(stderr, "Failed to allocate memory for the map\n");
		ret = -1;
		goto out;
	}

	new_map->seed = seed;
	new_map->buckets = buckets;
	new_map->num_buckets = num_buckets;
	new_map->compare_fn = compare_fn;

	*map = new_map;

out:
	return ret;
}

void hmap_finalize(struct hmap *map)
{
	int i;
	if (!map) return;

	int num_buckets = map->num_buckets;
	for (i = 0; i < num_buckets; i++) {
		struct bucket *b = &map->buckets[i];
		struct hash_node *head = b->head;
		/* free linked list */
		while (head) {
			struct hash_node *next = head->next;
			if (head->element) free(head->element);
			free(head);
			head = next;
		}
	}
	free(map->buckets);
	free(map);
}

/* load from text */
int load_hmap_from_file(char *path, struct hmap **pmap)
{
	int ret = 0;
	struct hmap *map = NULL;
	int num_lines = 0;
	char *line = NULL;
	size_t line_len = 0;

	FILE *fp = fopen(path, "r");
	if (!fp) {
		fprintf(stderr, "%s: Failed to open %s\n", __func__, path);
		ret = -1;
		goto out;
	}

	/* get the number of tokens */
	while (getline(&line, &line_len, fp) != -1) num_lines++;
	rewind(fp);

	ret = hmap_alloc(num_lines, NULL, &map);
	if (ret) {
		fprintf(stderr, "%s: Failed to create hash map\n", __func__);
		ret = -1;
		goto out;
	}

	/* read the tokens */
	while (getline(&line, &line_len, fp) != -1) {
		/* remove trailing \n and skip the empty line */
		line[strcspn(line, "\n")] = '\0';
		if (line[0] == '\0') continue;

		char *token = strdup(line);
		if (!token) {
			fprintf(stderr, "%s: failed to duplicate tok %s\n", __func__, line);
			ret = -1;
			goto out;
		}

		/* add to the map */
		ret = hmap_add_elem(token, NULL, map);
		if (ret) {
			fprintf(stderr, "%s: failed to add element %s to the map\n", __func__, line);
			goto out;
		}
	}

	*pmap = map;

out:
	free(line);
	if (fp) fclose(fp);
	if (ret) hmap_finalize(map);

	return ret;
}

/*

int main(int argc, char **argv) {
	int ret = 0;
	struct hmap *map = NULL;
	char *a = strdup("a");
	char *b = strdup("b");
	char *c = strdup("c");
	char *d = strdup("d");

	hmap_alloc(10, comp, &map);
	hmap_add_elem(a, a, map);
	hmap_add_elem(b, b, map);
	hmap_add_elem(c, c, map);
	hmap_add_elem(d, d, map);

	hmap_delete_elem("d", map);

	char *tok[10] = { "aaa", "bbb", "cccc", "a", "b", "c", "d", "dd", "ab", "ac"};
	int i;
	for (i = 0; i < 10; i++) {
		ret = hmap_lookup_elem(tok[i], map, NULL);
		(ret > 0)? printf("%s found\n", tok[i]) : printf("%s not found\n", tok[i]);
	}

	hmap_finalize(map);
	return 0;
}
*/
