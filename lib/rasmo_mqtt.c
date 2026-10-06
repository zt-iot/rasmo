#define _GNU_SOURCE
#define __USE_GNU
#include <sched.h>
#include <string.h>
#include <mosquitto.h>
#include <errno.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>

#include "rasmo_mqtt.h"

volatile int mqtt_connected = 0;
volatile uint64_t nmessage = 0;
uint64_t npuback = 0;
static uint64_t npublish = 0;


static void mqtt_on_publish(struct mosquitto *mosq, void *obj, int mid)
{
	(void)obj;
	(void)mid;
	(void)mosq;

	npuback++;
}

static void mqtt_on_connect(struct mosquitto *mosq, void *obj, int rc)
{
	(void)obj;
	(void)mosq;
    fprintf(stderr, "%s: CONNECTED rc=%d\n", __func__, rc);
    mqtt_connected = 1;
}

static void mqtt_on_message(struct mosquitto *mosq, void *obj, const struct mosquitto_message *message)
{
	(void)obj;
	(void)mosq;
	(void)message;
#if 0
    --mqtt_iter;
    /**/
    strncpy(mqtt_lastmsg, message->payload, 128);
    DEBUG {
	char	buf[128];
	strncpy(buf, message->payload, 10);
	buf[10] = 0;
	printf("%s:<%d> topc=\"%s\" msg(%s)\n", __func__, mqtt_iter, message->topic, buf);
	fflush(stdout);
    }
    if (mqtt_iter == 0) {
	DEBUG {
	    printf("%s: subscriber_bfd= %d\n", __func__, subscriber_bfd); fflush(stdout);
	}
	if (subscriber_bfd > 0) {
	    lockf(subscriber_bfd, F_ULOCK, 0);
	    lockf(subscriber_efd, F_ULOCK, 0);
	    mqtt_lockclose(subscriber_bfd);
	    mqtt_lockclose(subscriber_efd);
	}
	mqtt_fin(mosq);
	tm_et = tick_time();
	if (verbose) {
	    uint64_t	clk = tm_et - tm_st;
	    double	tm = (double)(clk)/((double)tm_hz/(double)SCALE);
	    printf("%s: time: %f (usec) (%ld), start: %ld, end: %ld, \n",
		   __func__, tm, clk, tm_st, tm_et); fflush(stdout);
	}
	exit(0);
    }

#endif
}

void mqtt_connect_callback_set(void *mqtt_inst, void *on_connect_func)
{
	void (*on_connect)(struct mosquitto*, void*, int) = NULL;
	struct mosquitto *mosq = (struct mosquitto *)mqtt_inst;

	on_connect = (void(*)(struct mosquitto*, void*, int))on_connect_func;
	if (on_connect) {
		mosquitto_connect_callback_set(mosq, on_connect);
	}
	else {
		mosquitto_connect_callback_set(mosq, mqtt_on_connect);
	}
}

void mqtt_message_callback_set(void *mqtt_inst, void *on_message_func)
{
	void (*on_message)(struct mosquitto*, void*, const struct mosquitto_message *) = NULL;
	struct mosquitto *mosq = (struct mosquitto *)mqtt_inst;

	on_message = (void(*)(struct mosquitto*, void*, const struct mosquitto_message *))on_message_func;
	if (on_message) {
		mosquitto_message_callback_set(mosq, on_message);
	}
	else {
		mosquitto_message_callback_set(mosq, mqtt_on_message);
	}
}

void mqtt_publish_callback_set(void *mqtt_inst, void *on_publish_func)
{
	void (*on_publish)(struct mosquitto*, void*, int) = NULL;
	struct mosquitto *mosq = (struct mosquitto *)mqtt_inst;

	on_publish = (void(*)(struct mosquitto*, void*, int))on_publish_func;
	if (on_publish) {
		mosquitto_publish_callback_set(mosq, on_publish);
	}
	else {
		mosquitto_publish_callback_set(mosq, mqtt_on_publish);
	}
}

void *mqtt_init(char *host, int port, int keepalive, void *on_connect, void *on_message, void *on_publish, void *user_data)
{
	int rc = 0;
	struct mosquitto *mosq = NULL;

	rc = mosquitto_lib_init();
	if (rc != MOSQ_ERR_SUCCESS) {
		fprintf(stderr, "mosquitto_lib_init: %s\n", mosquitto_strerror(rc));
		goto error;
	}

	mosq = mosquitto_new(NULL, true, user_data);
	if (!mosq) {
		perror("Failed to create a new client instance: ");
		goto error;
	}

	mqtt_connect_callback_set(mosq, on_connect);
	mqtt_message_callback_set(mosq, on_message);
	mqtt_publish_callback_set(mosq, on_publish);

	rc = mosquitto_connect(mosq, host, port, keepalive);
	if (rc != MOSQ_ERR_SUCCESS) {
		fprintf(stderr, "mosquitto_connect: %s\n", mosquitto_strerror(rc));
		goto error;
	}

	return (void*) mosq;

error:
	mosquitto_destroy(mosq);
	mosquitto_lib_cleanup();
	return NULL;
}

void mqtt_finalize(void *mqtt_inst)
{
	if (mqtt_inst) {
		struct mosquitto *mosq = (struct mosquitto *)mqtt_inst;

		mosquitto_disconnect(mosq);
		mosquitto_destroy(mosq);
		mosquitto_lib_cleanup();
	}
}

int mqtt_publish(void *mqtt_inst, const char *topic, int len, const char *msg, int qos)
{
	int	rc = 0;
	struct mosquitto *mosq = (struct mosquitto *) mqtt_inst;
	int mid = 0;

	rc = mosquitto_publish(mosq, &mid, topic, len, msg, qos, 0);
	if (rc != MOSQ_ERR_SUCCESS) {
		fprintf(stderr, "Publish msg ID %d failed ERROR %d\n", mid, rc);
		return -1;
	}

	npublish++;

	return 0;
}

int mqtt_subscribe(void *mqtt_inst, int *mid, const char *topic, int qos)
{
	int rc = 0;
	struct mosquitto *mosq = (struct mosquitto *)mqtt_inst;

	rc = mosquitto_subscribe(mosq, mid, topic, qos);
	if (rc != MOSQ_ERR_SUCCESS) {
		fprintf(stderr, "Failed to subscribe topic %s ERROR %d\n", topic, rc);
		return -1;
	}
	
	return 0;
}

/* MQTT v3 */
int mqtt_subscribe_multiple(void *mqtt_inst, int *mid, int topic_num,
					char *const *const topics, int qos)
{
	int rc = 0;
	struct mosquitto *mosq = (struct mosquitto *)mqtt_inst;

	rc = mosquitto_subscribe_multiple(mosq, mid, topic_num, topics, qos, 0, NULL);
	if (rc != MOSQ_ERR_SUCCESS) {
		fprintf(stderr, "mosquitto_subscribe_multiple: %s\n", mosquitto_strerror(rc));
		return -1;
	}
	return 0;
}

int mqtt_loop_start(void *mqtt_inst)
{
	struct mosquitto *mosq = mqtt_inst;
	mosquitto_loop_start(mosq);
	
	/* wait until on_connect callback is called
	 when broker sends a CONNACK message in response to a connection
	*/
	while (!mqtt_connected) usleep(10);

	return mqtt_connected;
}

int mqtt_loop_stop(void *mqtt_inst, int force)
{
	struct mosquitto *mosq = mqtt_inst;
	int ret = 0;

	ret = mosquitto_loop_stop(mosq, force);
	if (ret != MOSQ_ERR_SUCCESS) {
		fprintf(stderr, "mosquitto_loop_stop: %s\n", mosquitto_strerror(ret));
		return -1;
	}

	return ret;
}

int mqtt_loop_forever(void *mqtt_inst, int timeout, int max_packets)
{
	struct mosquitto *mosq = mqtt_inst;
	int ret = 0;
	
	(void)max_packets;
	
	/* max_packets is curretly unused and should be set to 1 for compatibility
	   based on https://mosquitto.org/api/files/mosquitto-h.html#mosquitto_loop_forever
	   auto-reconnect if connection failed
	*/
	ret = mosquitto_loop_forever(mosq, timeout, 1);
	if (ret != MOSQ_ERR_SUCCESS) {
		fprintf(stderr, "mosquitto_loop_forever: %s\n", mosquitto_strerror(ret));
		return -1;
	}
	
	return 0;
}

int mqtt_disconnect(void *mqtt_inst)
{
	struct mosquitto *mosq = mqtt_inst;
	int ret = 0;

	ret = mosquitto_disconnect(mosq);
	if (ret != MOSQ_ERR_SUCCESS && ret != MOSQ_ERR_NO_CONN) {
		fprintf(stderr, "mosquitto_disconnect: %s\n", mosquitto_strerror(ret));
		return -1;
	}

	return 0;
}

