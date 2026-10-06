#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <json-c/json.h>

#include <mosquitto.h>
#include <arpa/inet.h>
#include "rasmo_mqtt.h"
#include "access_netfilter.h"
#include "access_control.h"
#include "access_parser.h"
#include "access_db.h"
#include "access_sqlite3.h"

/* TODO list:

	Error handling: SQLITE_BUSY
*/

enum {
	TOPIC_SUCCESS = 0,
	TOPIC_FAIL,
	TOPIC_SYNC,
	NUM_SUB_TOPICS
};

enum {
	TOPIC_BLOCK = 0,
	TOPIC_SYNCACK,
	NUM_PUB_TOPICS
};

enum {
	BLOCK_CRITICAL = 0,
	BLOCK_HIGH,
	BLOCK_MEDIUM,
	BLOCK_LOW,
	BLOCK_LEVEL_NUM
};

char *sub_topics[NUM_SUB_TOPICS] = {
	[TOPIC_SUCCESS] = "local/audit/login/success",
	[TOPIC_FAIL] = "local/audit/login/failed",
	[TOPIC_SYNC] = "global/cpsp/sync/login",
};

char *pub_topics[NUM_PUB_TOPICS] = {
	[TOPIC_BLOCK] = "global/cpsp/report/login",
	[TOPIC_SYNCACK] = "global/cpsp/sync-ack/login",
};

// DEMO
#define RED    "\x1b[31m"
#define GREEN  "\x1b[32m"
#define RESET  "\x1b[0m"
#define BOLD   "\x1b[1m"	

struct mosquitto *mosq = NULL;
static struct json_tokener *tokener = NULL;
static const char *db_name = "locallog.db";
static const char *table_name = "local_state";

sqlite3 *db = NULL;

static void sig_handler(int sig)
{
//	fprintf(stderr, "Number of received msg: %ld\n", num_msg);
	(void) sig;
	if (mosq) {
		mqtt_disconnect(mosq);
		mqtt_finalize(mosq);
	}
	fingerprint_db_destroy();
	failed_hm_destroy();

	exit(EXIT_SUCCESS);
}

// TODO: assume that the numbers are configurable
//int maxretry_levels[BLOCK_LEVEL_NUM] = { 1, 3, 6, 9 };
int maxretry_levels[BLOCK_LEVEL_NUM] = { 0, 0, 0, 0 };

/* examples
topic: audit/login/failed
payload:
username="root" valid_user=yes
fingerprint=dfa2e43bde80c32f422f92ee98fb45c07a326627ee801ca51a6f08f466739510 ip_addr=xxx.xxx.xxx.xxx

topic: audit/login/success
payload:
username="jie" fingerprint=dfa2e43bde80c32f422f92ee98fb45c07a326627ee801ca51a6f08f466739510 ip_addr=xxx.xxx.xxx.xxx
*/
static inline int set_retry_policy(int valid_user, int fp_exist)
{
	int level = -1;

	if (valid_user & fp_exist)
		level = maxretry_levels[BLOCK_LOW];
	else if ((valid_user | fp_exist) == 0) 
		level = maxretry_levels[BLOCK_CRITICAL];
	else if (valid_user && !fp_exist) 
		level = maxretry_levels[BLOCK_HIGH];
	else
		level = maxretry_levels[BLOCK_MEDIUM];

	return level;
}

/* Payload to send to the Zabbix Data Receiver:
	{
		"block": ["ip1", "ip2"],
		"xid": "uint64_t string"
	}
	caller needs to free the payload buffer !!
 */
static int generate_payload(struct ip_batch *batch, int num, char **payload)
{
	int ret = 0, i;
	/* buf for xid8 uint64_t in string + '\0' */
	char xid[64] = { 0 };

	/* if input empty, do nothing */
	if (!batch || !num) return 0;

	json_object *top_obj = json_object_new_object();
	json_object *block_arr = json_object_new_array();
	json_object *unblock_arr = json_object_new_array();

	int num_block = 0, num_unblock = 0;

	/* encode IPs into respective JSON objects */
	for (i = 0; i < num; i++) {
		struct ip_batch *cur = &batch[i];
		int op = cur->op;
		char *ip = cur->ip_addr;

		if (op == OP_BLOCK) {
			json_object *obj = json_object_new_string(ip);
			json_object_array_add(block_arr, obj);
			num_block++;
		}
		else if (op == OP_UNBLOCK) {
			json_object *obj = json_object_new_string(ip);
			json_object_array_add(unblock_arr, obj);
			num_unblock++;
		}
		else {
			fprintf(stderr, "Invalid OP\n");
			ret = -1;
			goto out;
		}
	}

	/* if no block entries: free the array object */
	if (num_block) {
		json_object_object_add(top_obj, "block", block_arr);
	}
	else { json_object_put(block_arr); } 

	/* if no unblock entries: free the array object */
	if (num_unblock) {
		json_object_object_add(top_obj, "unblock", unblock_arr);
	}
	else { json_object_put(unblock_arr); }

	/* extract xid from kv-store */
	ret = query_xid_db(db, xid, sizeof(xid));
	if (ret) {
		fprintf(stderr, "Failed to retrieve latest xid\n");
		goto out;
	}

	/* encode xid into a string object */
	json_object *xid_obj = json_object_new_string(xid);
	json_object_object_add(top_obj, "xid", xid_obj);

	/* output into a compact string, no extra whitespace nor formatting */
	const char *str = json_object_to_json_string_ext(top_obj, JSON_C_TO_STRING_PLAIN);
	char *output = strdup(str);
	if (!output) {
		fprintf(stderr, "%s: strdup failed\n", __func__);
		ret = -1;
		goto out;
	}
	*payload = output;

out:
	if (top_obj) json_object_put(top_obj);
	return ret;
}

static int block_ip(char *ip)
{
	int ret = 0;
	char *payload = NULL;

	struct ip_batch batch = { 0 };
	batch.op = OP_BLOCK;
	snprintf(batch.ip_addr, IP_ADDR_LEN, "%s", ip);

// DEMO
//fprintf(stderr, BOLD RED"Attacking IP detected: %s\n"RESET, ip);

#ifdef ENABLE_COLLAB
	/* create record in DB if new; otherwise reset the record */
	ret = new_record_db(db, table_name, &batch, 1);
	if (ret) {
		fprintf(stderr, "Failed to create record\n");
		goto out;
	}
#endif
	/* perform block operation */
	ret = netfilter_op(&batch, 1);
	if (ret) {
		fprintf(stderr, "Failed to block IP\n");
		goto out;
	}

#ifdef ENABLE_COLLAB
// DEMO
//fprintf(stderr, BOLD RED"Attacking IP (%s) blocked\n"RESET, ip);

	/* commit */
	ret = commit_ip_db(db, table_name, &batch, 1);
	if (ret) {
		fprintf(stderr, "Failed to commit ip addr\n");
		goto out;
	}

	/* generate JSON string */
	ret = generate_payload(&batch, 1, &payload);
	if (ret) {
		fprintf(stderr, "Failed to generate payload\n");
		goto out;
	}

	ret = mqtt_publish(mosq, pub_topics[TOPIC_BLOCK], strlen(payload), payload, 2);
	if (ret) {
		fprintf(stderr, "Failed to publish %s to topic %s\n",
				payload, pub_topics[TOPIC_BLOCK]);
		ret = -1;
		goto out;
	}
#endif
// DEMO
//fprintf(stderr, BOLD GREEN"REPORT message sent:\n"RESET"%s\n", payload);

out:
	if (payload) free(payload);
	return ret;
}

/* recovery process after crash-reboot
   resend payload:

	{
		"block": ["ip1", "ip2"],
		"unblock": ["ip3"] 
		"xid": <int64>
	}
	In this framework, 'unblock' is restricted on devices.
	But in the implementation, 'unblock' key and field are supported
	for different use cases;

	TODO: restrict payload size
*/
static int restart_recovery(sqlite3 *db)
{
	int ret = 0;
	char xid[64] = { 0 };
	char xid_payload[64] = { 0 };

	char *payload = NULL;
	struct ip_batch *batch = NULL;
	struct ip_batch *batch_resend = NULL;
	int num = 0, num_resend = 0;

	/* extract xid from kv-store */
	ret = query_xid_db(db, xid, sizeof(xid));
	if (ret) {
		fprintf(stderr, "%s: Failed to retrieve latest xid\n", __func__);
		ret = -1;
		goto out;
	}

	snprintf(xid_payload, 64, "{\"xid\":\"%s\"}", xid);
// EVAL
//	snprintf(xid_payload, 64, "{\"xid\":\"0\"}");

	/* xid should be sent to sync.cursor on Zabbix regularly */
	ret = mqtt_publish(mosq, pub_topics[TOPIC_SYNCACK], strlen(xid_payload), xid_payload, 2);
	if (ret) {
		fprintf(stderr, "Failed to publish %s to topic %s\n",
				xid_payload, pub_topics[TOPIC_SYNCACK]);
		ret = -1;
		goto out;
	}

	/* restore local blocklist */
	ret = query_recov_db(db, table_name, &batch, &num);
	if (ret) {
		fprintf(stderr, "%s: Failed to get recovery entries\n", __func__);
		ret = -1;
		goto out;
	}
	/* skip if no blocked entries to restore*/
	if (!num) goto out;

	/* block batch in netfilter */
	ret = netfilter_op(batch, num);
	if (ret) {
		fprintf(stderr, "%s: Failed to recover blocklist\n", __func__);
		ret = -1;
		goto out;
	}

	/* commit batch */
	ret = commit_ip_db(db, table_name, batch, num);
	if (ret) {
		fprintf(stderr, "%s: Failed to commit\n", __func__);
		ret = -1;
		goto out;
	}

	/* extract the entries with sync=FALSE, resend */
	ret = query_resend_db(db, table_name, &batch_resend, &num_resend);
	if (ret) {
		fprintf(stderr, "%s: Failed to get resend entries\n", __func__);
		ret = -1;
		goto out;
	}
	/* skip resending if no unsync-ed entries */
	if (!num_resend) { goto out; }

	/* generate resend payload */
	ret = generate_payload(batch_resend, num_resend, &payload);
	if (ret) {
		fprintf(stderr, "%s: Failed to generate JSON payload\n", __func__);
		ret = -1;
		goto out;
	}

	/* send */
	ret = mqtt_publish(mosq, pub_topics[TOPIC_BLOCK], strlen(payload), payload, 2);
	if (ret) {
		fprintf(stderr, "Failed to publish %s to topic %s\n",
				payload, pub_topics[TOPIC_BLOCK]);
		ret = -1;
		goto out;
	}

out:
	if (batch) free(batch);
	if (batch_resend) free(batch_resend);
	if (payload) free(payload);
	return ret;
}

/* start recovery and subscription to the topics when connection succeeds */
void on_connect(struct mosquitto *mosq, void *obj, int rc)
{
	(void) obj;
	/* return if connection failed */
	if (rc) return;

#ifdef ENABLE_COLLAB
	/* recovery rebuild the blocklist */
	if (restart_recovery(db)) {
		fprintf(stderr, "%s: recovery failed\n", __func__);
		return;
	}
#endif

	/* p1: mqtt instance
	   p2: mid
	   p3: number of topics
	   p4: topic array
       p5: qos */
	if (mqtt_subscribe_multiple(mosq, NULL, NUM_SUB_TOPICS, sub_topics, 1)) {
		fprintf(stderr, "%s: subscription failed\n", __func__);
		return;
	}
}

/* TODO: validation on the number of elements passing to netfilter */
void on_message(struct mosquitto *mosq, void *obj, const struct mosquitto_message *message)
{
	int ret = 0, i;
	char *topic_name = message->topic;
	char *payload = (char *)message->payload;
	int payloadlen = message->payloadlen;

	(void)obj;

	/* TOPIC_SYNC: payload must be one JSON string in the format below; 
		restricted 
		{ 
			"block": ["ip1", "ip2", ...], 	# array of IPs
			"unblock": ["ip3"], 				# array of IPs
			"xid": "string of a uint64_t number" # biggest xid of the sync data
		}
		NOTE: its recommended to store integer out of 2^53 limit as string
			(bcz of serialization limit?)
	*/

#ifdef ENABLE_COLLAB
	if (!strcmp(topic_name, sub_topics[TOPIC_SYNC])) {
		/* message for sync from the zabbix server */
		json_object *top_obj = NULL;
		json_object *block_obj = NULL, *unblock_obj = NULL;
		json_object *xid_obj = NULL;

		enum json_tokener_error json_err;
		const char *xid_str = NULL;
		char xid_payload[64] = { 0 };
		int xid_len = 0;

		int block_size = 0, unblock_size = 0;
		struct ip_batch *batch = NULL;
		int num_elements = 0;
		int idx = 0;

		json_tokener_reset(tokener);

		/* parse payload */
		top_obj = json_tokener_parse_ex(tokener, payload, payloadlen);
		json_err = json_tokener_get_error(tokener);
		if (!top_obj || json_err != json_tokener_success) {
			fprintf(stderr, "Failed to parse sync payload: %s\n",
				json_tokener_error_desc(json_err));
			goto out;
		}

// DEMO
//fprintf(stderr, BOLD GREEN"SYNC message:\n"RESET"%s\n", payload);

		/* block JSON array object */
		ret = json_object_object_get_ex(top_obj, "block", &block_obj);
		if (ret) { block_size = json_object_array_length(block_obj); }

		/* unblock JSON array object */
		ret = json_object_object_get_ex(top_obj, "unblock", &unblock_obj);
		if (ret) { unblock_size = json_object_array_length(unblock_obj); }

		/* xid object */
		ret = json_object_object_get_ex(top_obj, "xid", &xid_obj);
		if (!ret) {
			fprintf(stderr, "Sync message no xid key found\n");
			goto out;
		}
		xid_str = json_object_get_string(xid_obj);
		xid_len = json_object_get_string_len(xid_obj);
		if (!xid_len || xid_len > 20) {
			fprintf(stderr, "Invaid Xid field\n");
			goto out;
		}

		/* extract values from block/unblock array objects */
		num_elements = block_size + unblock_size;

		/* return if both array empty */
		if (!num_elements) goto out;

		batch = calloc(num_elements, sizeof(struct ip_batch));
		if (!batch) {
			fprintf(stderr, "ERROR: batch allocation: oom\n");
			goto out;
		}

		/* get the values of block array */
		for (i = 0; i < block_size; i++) {
			json_object *val_obj = json_object_array_get_idx(block_obj, i);
			const char *ip = json_object_get_string(val_obj);
			struct ip_batch *cur = &batch[idx++];

			cur->op = OP_BLOCK;
			snprintf(cur->ip_addr, IP_ADDR_LEN, "%s", ip);
		}

		/* get the values of unblock array */
		for (i = 0; i < unblock_size; i++) {
			json_object *val_obj = json_object_array_get_idx(unblock_obj, i);
			const char *ip = json_object_get_string(val_obj);
			struct ip_batch *cur = &batch[idx++];

			cur->op = OP_UNBLOCK;
			snprintf(cur->ip_addr, IP_ADDR_LEN, "%s", ip);
		}

		/* block & unblock in one transaction */
		ret = netfilter_op(batch, num_elements);
		if (ret) {
			fprintf(stderr, "failed to block the batch\n");
			goto out;
		}

		/* db update in transaction */
		ret = sync_ip_db(db, table_name, xid_str, batch, num_elements);
		if (ret) {
			fprintf(stderr, "failed to sync to db\n");
			goto out;
		}

// DEMO
//fprintf(stderr, GREEN"SYNC message deployed\n"RESET);

// FIXME: EVAL
//		snprintf(xid_payload, 64, "{\"xid\":\"0\"}");
		snprintf(xid_payload, 64, "{\"xid\":\"%s\"}", xid_str);
		/* pub ack if all the operations above succeed */
		ret = mqtt_publish(mosq, pub_topics[TOPIC_SYNCACK],
					strlen(xid_payload), xid_payload, 2);
		if (ret) {
			fprintf(stderr, "Failed to publish %s to topic %s\n",
					xid_payload, pub_topics[TOPIC_SYNCACK]);
			goto out;
		}
// DEMO
//fprintf(stderr, BOLD GREEN"SYNC-ACK message sent:\n"RESET "%s\n", xid_payload);

out:
		if (batch) free(batch);
		/* release the JSON object */
		json_object_put(top_obj);

	}
	else {
#else
	{
#endif
		/* messages from Linux Audit to detect malicious IP */
		char fingerprint[FINGERPRINT_LEN] = { 0 };
		char ip[IP_ADDR_LEN] = { 0 };

		ret = extract_fingerprint(fingerprint, payload, sizeof(fingerprint));
		if (ret) {
			fprintf(stderr, "Failed to get username from: %s\n", payload);
			return;
		}
	
		/* extract IP address from the record */
		ret = extract_ipaddr(ip, payload, sizeof(ip));
		if (ret) {
			fprintf(stderr, "Failed to get IP from: %s\n", payload);
			return;
		}

		/*
			success -> add to fingerprint db;
			failed -> start blocking logic
		*/
		if (!strcmp(topic_name, sub_topics[TOPIC_SUCCESS])) {
			ret = fingerprint_add(fingerprint);
			if (ret) {
				fprintf(stderr, "Failed to update fingerprint DB: %s\n", payload);
				return;
				/* TODO: error handling */
			}
	
			/* delete IP from failed DB if exists */
			failed_delete(ip);
		}
		else if (!strcmp(topic_name, sub_topics[TOPIC_FAIL])) {
			/* check risk score, and update maxretry if needed */
			struct access_attempt *attempt = NULL;
			char valid_str[8] = { 0 };
			char valid_user = 1;
			char username[LOGIN_NAME_MAX] = { 0 };
			int maxretry = 0, exist_fp = 0;
	
			ret = extract_username(username, payload, sizeof(username));
			if (ret) {
				fprintf(stderr, "Failed to get username from: %s\n", payload);
				return;
				/* TODO: error handling, should add num_failed here too?
					invalid input username format/length
				 */
			}
	
			ret = extract_validuser(valid_str, payload, sizeof(valid_str));
			if (ret) {
				fprintf(stderr, "Failed to get valid_user from: %s\n", payload);
				return;
				/* TODO: error handling */
			}
	
			/* login with root admin is marked as invalid */
			if (!strcmp(valid_str, "no") ||
				!strcmp(username, "root") ||
				!strcmp(username, "admin")) {
				valid_user = 0;
			}

			exist_fp = (fingerprint_query(fingerprint) < 0)? 0 : 1;
			/* set maxretry rule by valid_user & fingerprint */
			maxretry = set_retry_policy(valid_user, exist_fp);
	
			/* check if the same IP has failed history */
			ret = failed_query(ip, (void **)&attempt);
			if (ret > 0) {
				/* already has, update #fails, maxretry if needed*/
				int num_failed = ++(attempt->num_failed);
				int maxretry_min = attempt->maxretry;
	
				if (maxretry < maxretry_min) {
					attempt->maxretry = maxretry_min = maxretry;
				}
	
				/* if the number of fails beyond maxretry, block IP */
				if (num_failed >= maxretry_min) {
					ret = block_ip(ip);
					if (ret) {
						/* TODO: error handling */
						fprintf(stderr, "Failed to block IP %s\n", ip);
						return;
					}
	
					/* delete from hash map after block */
					ret = failed_delete(ip);
					if (ret) {
						/* TODO: error handling */
						fprintf(stderr, "Failed to delete %s from failed DB\n", ip);
						return;
					}
				}
			}
			else if (!ret) {
				/* first fail: if maxretry is 0, block now */
				if (!maxretry) {
					ret = block_ip(ip);
					if (ret) {
						/* TODO: error handling */
						fprintf(stderr, "Failed to block IP %s\n", ip);
						return;
					}
				}
				else {
					ret = failed_add(ip, maxretry, fingerprint);
					if (ret) {
						/* TODO: error handling */
						fprintf(stderr, "Failed to create failed entry: %s\n", payload);
						return;
					}
				}
			}
			else {
				fprintf(stderr, "%s: failed query error\n", __func__);
				return;
			}
		}
		else {
			fprintf(stderr, "Invalid topic: %s, but how?\n", topic_name);
			return;
		}
	}
}

int main(int argc, char **argv) {
	int ret = 0;
	char *host = "localhost";
    int	keepalive = 600;
    int	port = 1883;
	struct sigaction sa;

	(void)argc;
	(void)argv;

	// init signal handlers
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = sig_handler;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

	/* tokener for parsing SYNC message */
	tokener = json_tokener_new();
	if (!tokener) {
		fprintf(stderr, "Failed to create a JSON tokener\n");
		ret = -1;
		goto out;
	}
	json_tokener_set_flags(tokener, JSON_TOKENER_STRICT);

	/* regex for audit message: should use JSON too */
	ret = init_regex_parser();
	if (ret) {
		fprintf(stderr, "Failed to init parsers\n");
		goto out;
	}

#ifdef ENABLE_COLLAB
	/* init SQLite */
	ret = init_sqlite_db(db_name, table_name, &db);
	if (ret) {
		fprintf(stderr, "Failed to init SQLite db\n");
		goto out;
	}
#endif

	/* init netfilter firewall structure for IP blocking/unblocking
		lose on reboot; no-op if the structure already exists in the kernel */
	ret = netfilter_init();
	if (ret) {
		fprintf(stderr, "Failed to init netfilter blocklist db\n");
		goto out;
	}

	/* failed attempts tracking hashmap */
	ret = failed_hm_init();
	if (ret) {
		fprintf(stderr, "Failed to initialize failed attempt DB\n");
		ret = -1;
		goto out;
	}

	/* fingerprint array */
	ret = fingerprint_db_init(0);
	if (ret) {
		fprintf(stderr, "Failed to initialize fingerprint DB\n");
		ret = -1;
		goto out;
	}

	/* init MQTT */
	mosq = mqtt_init(host, port, keepalive, on_connect, on_message, NULL, NULL);
	if (!mosq) {
		fprintf(stderr, "Failed to initialize MQTT\n");
		ret = -1;
		goto out;
	}

	/* recovery and topic subscription in on_connect callback */

	/* mosq, timeout (-1 for default 1s), max_packets (unused, should be set to 1) */
    ret = mqtt_loop_forever(mosq, -1, 1);
    if (ret) {
		fprintf(stderr, "mqtt_loop_forever error %d\n", ret);
		ret = -1;
		goto out;
    }

out:
	if (tokener) json_tokener_free(tokener);
	fingerprint_db_destroy();
	failed_hm_destroy();
	finalize_sqlite_db(db);
	mqtt_finalize(mosq);

	return ret;
}
