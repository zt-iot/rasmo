#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <mosquitto.h>
#include <signal.h>
#include <dirent.h>
#include <errno.h>
#include <json-c/json.h>
#include <sys/stat.h>

#include "rasmo_mqtt.h"
#include "rasmo_util.h"
#include "sysfilter.h"
#include "sysfilter_parser.h"

#define OUTPUT_DIR "output"

struct mosquitto *mosq = NULL;

int num_apps = 0;
struct rt_app_profile *apps = NULL;

#define ROOT_TOPIC "local/audit/syscall"
static char *audit_topic = ROOT_TOPIC "/#";
static char *anomaly_topic = "global/cpsp/report/syscall";

static void finalize_apps(struct rt_app_profile *apps)
{
	if (apps) {
		int i;
		for (i = 0; i < num_apps; i++) {
			struct rt_app_profile *cur_app = &apps[i];

			free(cur_app->app_path);
			free(cur_app->app_path_hex);
			hmap_finalize(cur_app->profile);
		}
		free(apps);
	}
}

static inline int report_anomaly(char *app_name, char *token)
{
	int ret = 0, len = 0;
	char anomaly[INITIAL_BUFFER_LEN] = { 0 };

	len = sprintf(anomaly, "APP(%s) Token failed: %s", app_name, token);

	//DEBUG
	(void) len;
	fprintf(stderr, "%s\n", anomaly);
//	ret = mqtt_publish(mosq, anomaly_topic, len, anomaly, 2);
//	if (ret) {
//		fprintf(stderr, "PID: %d Failed to publish %s to topic %s\n", token, anomaly_topic);
//		return -1;
//	}

	return ret;
}

void on_message(struct mosquitto *mosq, void *obj, const struct mosquitto_message *message)
{
	(void) mosq;
	(void) obj;
	
	char *payload = message->payload;
	//pid_t pid = -1;
	int ret = 0; 
	char encoded_path[MQTT_TOPIC_LEN_MAX] = { 0 };
	struct rt_app_profile *cur_app = NULL;
	char token[INITIAL_BUFFER_LEN] = { 0 };
	struct hmap *map = NULL;
	char *topic = strdup(message->topic);
	if (!topic) {
		perror("strdup failed:");
		return;
	}
	size_t root_len = strlen(ROOT_TOPIC);
	size_t topic_len = strlen(topic);

	if (topic_len <= root_len) {
		free(topic);
		return;
	}

	/* skip root topic */
	char *st = topic + root_len;
	while (*st == '/') st++;
	if (*st == '\0') {
		/* it's root topic with extra slash / */
		free(topic);
		return;
	}

	/* otherwise there are sub-topics */
	char *end = strchr(st, '/');
	if (!end) {
		end = topic + strlen(topic);
	}
	*end = '\0';

	ret = snprintf(encoded_path, MQTT_TOPIC_LEN_MAX, "%s", st);
	if (ret < 0 || ret >= MQTT_TOPIC_LEN_MAX) {
		fprintf(stderr, "%s: Invalid exe path\n", __func__);
		free(topic);
		return ;
	} 
	free(topic);

	// identify app
	int i;
	for (i = 0; i < num_apps; i++) {
		struct rt_app_profile *app_iter = &apps[i];

		char *hex_name = app_iter->app_path_hex;
		if (!strcmp(hex_name, encoded_path)) {
			cur_app = app_iter;
			break;
		}
	}

	if (!cur_app) {
		fprintf(stderr, "Could not find app data %s; Skip\n", encoded_path);
		return ;
	}

	map = cur_app->profile;

	ret = parse_record(payload, (char *)token);
	if (ret < 0) {
		fprintf(stderr, "on_message verify_record error\n");
		return ;
	}

//DEBUG
//fprintf(stderr, "payload: %s\ntoken: %s\n", payload, token);

	/* query hash map here */
	ret = hmap_lookup_elem(token, map, NULL);
	if (ret < 0) {
		fprintf(stderr, "%s: verification failure for %s\n", __func__, payload);
		return ;
	}
	else if (!ret) {
		/* not found: report */
		ret = report_anomaly(cur_app->app_path, token);
		if (ret) {
			fprintf(stderr, "Failed to report anomaly\n");
			return ;
		}	
	}
}

static int count_file_num(char *dir, unsigned char type, int *num)
{
	int ret = 0;
	DIR *dp = NULL; struct dirent *entp = NULL;
	int num_files = 0;

	dp = opendir(dir);
	if (!dp) {
		perror("Failed to open output directory:");
		ret = -1;
		goto out;
	}

	while ((entp = readdir(dp))) {
		char *name = entp->d_name;
		if (name[0] == '.') continue;

		if (entp->d_type == type) num_files++;
	}
	
	if (dp) closedir(dp);
	*num = num_files;

out:
	return ret;
}

static int load_path_from_json(char *json_path, char **output)
{
	int ret = 0;
	json_object *profile_obj = NULL;

	/* get object from file */
	profile_obj = json_object_from_file(json_path);
	if (!profile_obj) {
		fprintf(stderr, "Failed to get object from %s\n", json_path);
		ret = -1;
		goto out;
	}

	char *exe_key = "exe";
	json_object *exe_object = NULL;

	ret = json_object_object_get_ex(profile_obj, exe_key, &exe_object);
	if (!ret) {
		fprintf(stderr, "%s: Key does not exist: %s\n", __func__, exe_key);
		ret = -1;
		goto out;
	}

	const char *exe_str = json_object_get_string(exe_object);
	if (!exe_str) {
		fprintf(stderr, "%s: Failed to read path\n", __func__);
		ret = -1;
		goto out;
	}

	*output = strdup(exe_str);
	ret = 0;

out:
	if (ret) *output = NULL;
	json_object_put(profile_obj);
	return ret;
}

int load_app_profile(char *output_dir, struct rt_app_profile **app_p, int *num_app)
{
	int ret = 0, num_exec = 0;
	int i = 0;
	char token_path[PATH_MAX] = { 0 };
	char json_path[PATH_MAX] = { 0 };
	struct rt_app_profile *app_info = NULL;
	DIR *dp = NULL; struct dirent *entp = NULL;

	ret = count_file_num(output_dir, DT_DIR, &num_exec);
	if (ret) {
		fprintf(stderr, "Failed to get number of files in %s\n", output_dir);
		goto out;
	}
		
	// allocate info struct for all the apps
	app_info = calloc(num_exec, sizeof(struct rt_app_profile));
	if (!app_info) {
		perror("Failed to alloc memory for app info: ");
		ret = -1;
		goto out;
	}

	dp = opendir(output_dir);
	if (!dp) {
		perror("Failed to open output directory:");
		ret = -1;
		goto out;
	}

	while ((entp = readdir(dp))) {
		char *name = entp->d_name;
		/* skip non-directories, ., .., or hidden ones */
		if (name[0] == '.' || !(entp->d_type == DT_DIR)) continue;

		struct rt_app_profile *app = &app_info[i++];
		struct hmap *map = NULL;

		if (snprintf(token_path, PATH_MAX, "%s/%s/%s.tok",
				output_dir, name, name) >= PATH_MAX) {
			fprintf(stderr, "%s: Invalid path\n", __func__);
			ret = -1;
			goto out;
		}

		if (snprintf(json_path, PATH_MAX, "%s/%s/%s.json",
				output_dir, name, name) >= PATH_MAX) {
			fprintf(stderr, "%s: Invalid path\n", __func__);
			ret = -1;
			goto out;
		}

		/* get exe name from json and encode */
		ret = load_path_from_json(json_path, &app->app_path);
		if (ret) {
			fprintf(stderr, "Failed to load exe path\n");
			goto out;
		}

		ret = encode_exe_name(app->app_path, &app->app_path_hex);
		if (ret) {
			fprintf(stderr, "Failed to encode exe path\n");
			goto out;
		}

		ret = load_hmap_from_file(token_path, &map);
		if (ret) {
			fprintf(stderr, "Failed to load hashmap \n");
			goto out;
		}
		app->profile = map;
	}

	ret = 0;

	*app_p = app_info;
	*num_app = i;

out:
	/* free all the previous allocation if error happens */
	if (ret && app_info) {
		int j;
		for (j = 0; j < i; j++) {
			free(app_info[j].app_path);
			free(app_info[j].app_path_hex);
			hmap_finalize(app_info[j].profile);
		}
		free(app_info);
	}
	if (dp) closedir(dp);
	return ret;
}

static void sig_handler(int sig)
{
	(void) sig;
	if (mosq) {
		mqtt_disconnect(mosq);
		mqtt_finalize(mosq);
	}
	if (apps) finalize_apps(apps);

	exit(EXIT_SUCCESS);
}

static void usage(char *argv0)
{
	fprintf(stderr, "%s -i <output_path>\n", argv0);
}

static void init_sighandler(void)
{
	struct sigaction sa = { 0 };

	// init signal handlers
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = sig_handler;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
}

void on_connect(struct mosquitto *mosq, void *obj, int rc)
{
	(void) obj;
	if (rc) return;

	/* subscribe to the topic if connection succeeds */
	if (mqtt_subscribe(mosq, NULL, audit_topic, 1))
	{
		perror("mqtt_subscribe failed: ");
		return;
	}
	
}

int main(int argc, char **argv)
{
    int ret = 0, opt = 0;
	char *host = "localhost";
    int	keepalive = 600;
    int	port = 1883;
	char *output_path = NULL;

	while ((opt = getopt(argc, argv, "i:")) != -1) {
		switch (opt) {
			case 'i':
				output_path = optarg;
				break;
			default:
				fprintf(stderr, "Invalid argument: %c\n", optopt);
				usage(argv[0]);
				goto out;
		}
	}

	if (!output_path) {
		output_path = OUTPUT_DIR;
	}

	/* check if the provided profile directory exists */
	struct stat dir_stat = { 0 };
	ret = stat(output_path, &dir_stat);
	if (ret || !S_ISDIR(dir_stat.st_mode)) {
		fprintf(stderr, "Invalid profile path: %s\n", output_path);
		goto out;
	}

	init_sighandler();

	// read app profile 
	ret = load_app_profile(output_path, &apps, &num_apps);
	if (ret) {
		fprintf(stderr, "Failed to load app info from %s\n", OUTPUT_DIR);
		goto out;
	}

	ret = init_regex_parser();
	if (ret) {
		fprintf(stderr, "Failed to init regex parser\n");
		goto out;
	}

	mosq = mqtt_init(host, port, keepalive, on_connect, on_message, NULL, NULL);
	if (!mosq) {
		fprintf(stderr, "Failed to initialize MQTT\n");
		ret = -1;
		goto out;
	}

    ret = mqtt_loop_forever(mosq, -1, 1);
    if (ret) {
		fprintf(stderr, "mqtt_loop_forever error %d\n", ret);
		ret = -1;
		goto out;
    }

out:
	mqtt_finalize(mosq);
	finalize_apps(apps);

	return ret;
}
