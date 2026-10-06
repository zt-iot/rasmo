CC ?= gcc
CFLAGS ?= -Wall -Wextra -O2 -DENABLE_COLLAB

SRC_DIR := src
LIB_DIR := lib

MQTT_LDFLAGS += -lrasmo_mqtt -lmosquitto
HM_LDFLAGS += -lrasmo_hashmap -lxxhash

INCLUDES += -I/usr/local/include -I$(HOME)/install/include -I./include
LIBS += -L/usr/local/lib -L$(HOME)/install/lib -Llib/

LOGIN_LDFLAGS  += -lnftnl -lmnl -lsqlite3 -ljson-c $(MQTT_LDFLAGS) $(HM_LDFLAGS)
PLUGIN_LDFLAGS += -laudit -lauparse -lrasmo_util $(MQTT_LDFLAGS)
SYSFTR_LDFLAGS += -lrasmo_util -ljson-c $(MQTT_LDFLAGS) $(HM_LDFLAGS)

SCMP_LDFLAGS ?= -ljson-c -lrasmo_util
SCMP_RT_LDFLAGS ?= -lseccomp -ljson-c -lrasmo_util $(HM_LDFLAGS) $(MQTT_LDFLAGS)

TARGETS := login_filter monitor_plugin seccomp_create seccomp_loader sysfilter

RASMOLIB_SRC := $(wildcard $(LIB_DIR)/*.c)
RASMOLIB_OBJ := $(RASMOLIB_SRC:.c=.o)
RASMOLIBS := $(patsubst $(LIB_DIR)/%.c, $(LIB_DIR)/lib%.a, $(RASMOLIB_SRC))

LIB_UTIL    := $(LIB_DIR)/librasmo_util.a
LIB_MQTT    := $(LIB_DIR)/librasmo_mqtt.a
LIB_HASHMAP := $(LIB_DIR)/librasmo_hashmap.a

LOGIN_SRC  := $(wildcard $(SRC_DIR)/access_*.c) 
PLUGIN_SRC := $(wildcard $(SRC_DIR)/audit_plugin*.c)
SYSFTR_SRC := $(wildcard $(SRC_DIR)/sysfilter*.c)

SCMP_CMN_SRC := $(addprefix $(SRC_DIR)/, seccomp_json.c seccomp_util.c)
SCMP_SRC := $(addprefix $(SRC_DIR)/, seccomp_create.c seccomp_parser.c)
SCMP_RT_SRC := $(addprefix $(SRC_DIR)/, seccomp_loader.c seccomp_rt_parser.c)

LOGIN_OBJ  := $(LOGIN_SRC:.c=.o)
PLUGIN_OBJ := $(PLUGIN_SRC:.c=.o)
SYSFTR_OBJ := $(SYSFTR_SRC:.c=.o)

SCMP_CMN_OBJ := $(SCMP_CMN_SRC:.c=.o)
SCMP_OBJ := $(SCMP_SRC:.c=.o)
SCMP_RT_OBJ := $(SCMP_RT_SRC:.c=.o)

HEADERS := $(wildcard src/*.h) $(wildcard include/*.h)

.PHONY: all clean install

all: $(RASMOLIBS) $(TARGETS)

$(LIB_DIR)/lib%.a: $(LIB_DIR)/%.o
	ar rcs $@ $^

login_filter: $(LOGIN_OBJ) $(LIB_MQTT) $(LIB_HASHMAP)
	$(CC) $(LIBS) $(filter %.o,$^) -o $@ $(LOGIN_LDFLAGS)
	@sudo setcap cap_net_admin+ep ./$@

monitor_plugin: $(PLUGIN_OBJ) $(LIB_UTIL) $(LIB_MQTT)
	$(CC) $(LIBS) $(filter %.o,$^) -o $@ $(PLUGIN_LDFLAGS)

seccomp_create: $(SCMP_OBJ) $(SCMP_CMN_OBJ) $(LIB_UTIL)
	$(CC) $(LIBS) $(filter %.o,$^) -o $@ $(SCMP_LDFLAGS)

seccomp_loader: $(SCMP_RT_OBJ) $(SCMP_CMN_OBJ) $(LIB_UTIL) $(LIB_MQTT) $(LIB_HASHMAP)
	$(CC) $(LIBS) $(filter %.o,$^) -o $@ $(SCMP_RT_LDFLAGS)

sysfilter: $(SYSFTR_OBJ) $(LIB_UTIL) $(LIB_MQTT) $(LIB_HASHMAP)
	$(CC) $(LIBS) $(filter %.o,$^) -o $@ $(SYSFTR_LDFLAGS)

%.o: %.c $(HEADERS)
	$(CC) $(INCLUDES) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(RASMOLIB_OBJ) $(RASMOLIBS) $(LOGIN_OBJ) $(PLUGIN_OBJ) \
		$(SCMP_CMN_OBJ) $(SCMP_OBJ) $(SCMP_RT_OBJ) $(SYSFTR_OBJ) \
		$(TARGETS)

INSTALL_BINS := monitor_plugin sysfilter seccomp_loader login_filter
INSTALL_DIR  := /usr/local/sbin

install:
	$(if $(wildcard $(INSTALL_BINS)), \
		sudo cp $(wildcard $(INSTALL_BINS)) $(INSTALL_DIR), \
		@echo "install: no binaries built, nothing to copy")
