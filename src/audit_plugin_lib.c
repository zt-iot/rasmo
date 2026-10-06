#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <libaudit.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

#include "rasmo_mqtt.h"
#include "audit_plugin_lib.h"

volatile int stop = 0, hup = 0;
volatile int finish = 0;

int mqtt_on = 0; // MQTT off by default
int	num_sysc = 0;

static void term_handler(int sig)
{
	(void)sig;
    stop = 1;
}

static void hup_handler(int sig)
{
	(void)sig;
    printf("SIGHUP received\n"); fflush(stdout);
    hup = 1;
}

static void child_handler(int sig)
{
	(void)sig;
    printf("Child exiting\n"); fflush(stdout);
    finish = 1;
}

/* Register sighandlers */
static void register_sighandlers(void)
{
	struct sigaction sa;

	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);

	sa.sa_handler = term_handler;
	sigaction(SIGTERM, &sa, NULL);

	sa.sa_handler = hup_handler;
	sigaction(SIGHUP, &sa, NULL);
	
	sa.sa_handler = child_handler;
	sigaction(SIGCHLD, &sa, NULL);
}

/* mqtt=0 or 1 for now */
static int init_args(char *argv1)
{
	if (!strlen(argv1)) { return 0; }

	if (!strncmp(argv1, "mqtt=", 5)) {
		char *value = argv1 + 5;
		char *endptr = NULL;

		mqtt_on = strtol(value, &endptr, 10);
		if (*endptr != '\0') {
			fprintf(stderr, "Invalid args value to plugin: %s\n", argv1);
			return -1;
		}
	}
	else {
		fprintf(stderr, "Invalid args: %s\n", argv1);
		return -1;
	}

	return 0;
}

static int init_auparselib(auparse_state_t **au, auparse_callback_ptr auparse_callback)
{
	int rc = 0;

	auparse_state_t *_au = auparse_init(AUSOURCE_FEED, 0);
	if (!_au) {
		perror("auparse_init failed: ");
		rc = -1;
		goto out;
	}
	
	// Set the end of event timeout value
	rc = auparse_set_eoe_timeout(2);
	if (rc) {
		perror("auparse_set_eoe_timeout: ");
		goto out;
	}
	// Add a callback handler for notification
	auparse_add_callback(_au, auparse_callback, NULL, NULL);

out:
	*au = _au;
	return rc;
}

int plugin_init(char *argv1, void **mqtt_s, auparse_state_t **p_au, auparse_callback_ptr auparse_callback)
{
	int rc = 0;

	register_sighandlers();
	
	if (argv1) {
		rc = init_args(argv1);
		if (rc) {
			fprintf(stderr, "Error to parse args to plugin\n\n");
			goto out;
		}
	}

	if (p_au) {
		// initialize auparse library
		rc = init_auparselib(p_au, auparse_callback);
		if (rc) {
			perror("Failed to initialize auparselib: ");
			goto out;
		}
	}

	// connect to the local MQTT server
	if (mqtt_on && mqtt_s) {
		char *host = "localhost";
		int port = 1883;
		int keepalive = 60;
		void *tmp_mqtt = NULL;

		tmp_mqtt = mqtt_init(host, port, keepalive, NULL, NULL, NULL, NULL);
		if (!tmp_mqtt) {
			fprintf(stderr, "Error in MQTT initialization\n");
			*mqtt_s = NULL;
			rc = -1;
			goto out;
		}

		/* start MQTT thread to process network traffic */
		mqtt_loop_start(tmp_mqtt);
		//fprintf(stderr, "Broker: connected\n");

		*mqtt_s = tmp_mqtt;
	}

out:
	return rc;
}

void plugin_finalize(auparse_state_t *au, void *mqtt_inst)
{
	if (au) {
		auparse_flush_feed(au);
		auparse_destroy(au);
	}
	if (mqtt_inst) {
		mqtt_finalize(mqtt_inst);
	}
}
