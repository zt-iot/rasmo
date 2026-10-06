#ifndef __MQTT_TEST_H
#define __MQTT_TEST_H

#define MQTT_TOPIC_LEN_MAX 65536

void mqtt_publish_callback_set(void *mqtt_inst, void *on_publish_func);
void *mqtt_init(char *host, int port, int keepalive, void *on_connect, void *on_message, void *on_publish, void *user_data);
void mqtt_finalize(void *mqtt_inst);
int mqtt_publish(void *mqtt_inst, const char *topic, int len, const char *msg, int qos);
int mqtt_subscribe(void *mqtt_inst, int *mid, const char *topic, int qos);
int mqtt_subscribe_multiple(void *mqtt_inst, int *mid, int topic_num, char *const *const topics, int qos);
int mqtt_loop_start(void *mqtt_inst);
int mqtt_loop_stop(void *mqtt_inst, int force);
int mqtt_loop_forever(void *mqtt_inst, int timeout, int max_packets);
int mqtt_disconnect(void *mqtt_inst);
#endif
