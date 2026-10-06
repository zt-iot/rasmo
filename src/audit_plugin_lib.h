#ifndef __PLUGIN_TEST_H_
#define __PLUGIN_TEST_H_

#include <auparse.h>

extern volatile int stop;
extern volatile int hup;

int plugin_init(char *argv1, void **mqtt_s, auparse_state_t **p_au, auparse_callback_ptr auparse_callback);
void plugin_finalize(auparse_state_t *au, void *mqtt_inst);
#endif
