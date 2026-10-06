## Set the governer

Remember to set the governer of CPUs to *performance* before evaluation.
Run `./script/workload/set_governors.sh`

Check current governors:

```
sudo cat /sys/devices/system/cpu/cpu\*/cpufreq/scaling_governor
```

## Apps setup
The steps and dependencies for the applications used for evaluation.

#### Camera

Install libcamera, gstreamer, and flask:

```sh
sudo apt install libcamera-apps
sudo apt install libgstreamer1.0-dev \
	libgstreamer-plugins-base1.0-dev \
	gstreamer1.0-tools \
	gstreamer1.0-plugins-base \
	gstreamer1.0-plugins-good \
	gstreamer1.0-plugins-bad
pip install flask flask-restful
```

#### Dropbear (patched version needs libaudit)

Build patched Dropbear SSH server from source code:
```sh
./configure --disable-syslog LIBS=-laudit
make -j PROGRAMS="dropbear dbclient dropbearkey dropbearconvert"
sudo make PROGRAMS="dropbear dbclient dropbearkey dropbearconvert" install
```

Set up Dropbear server:

1. generate server keys

```
dropbearkey -t rsa -f dropbear_rsa_host_key
dropbearkey -t ecdsa -f dropbear_ecdsa_host_key
dropbearkey -t ed25519 -f dropbear_ed25519_host_key
```

2. move the generated keys to the folder `/etc/dropbear`; create the folder if it does not exist

3. run the Dropbear server with root

	`sudo dropbear -F -p <port number>`

`-F`: don't fork into background
`-p`: port number

Note that with syslog disabled, there is no -E option

## RASMO on-device setup

[x] Install Linux Audit:

```
sudo apt install libaudit-dev libauparse-dev auditd
```

[x] Setup Audit plugin:

Can find plugin location in `audit.conf`, by default the plugin config files should locate at `/etc/audit/plugins.d`.

[x] Install libmosquitto

```
sudo apt install mosquitto mosquitto-clients mosquitto-dev libmosquitto-dev
```

[x] Set up mosquitto.conf from the example

See `rasmo/config/mosquitto.conf`

[x] Install libjson-c and xxhash

```
sudo apt install libjson-c-dev libxxhash-dev
```

[x] libseccomp

```
sudo apt install libseccomp-dev
```

[x] login filter libs (libmnl, sqlite3, etc.)

```
sudo apt install sqlite3 libsqlite3-dev libnftnl-dev libmnl-dev
```

[x] Zabbix agent, PSK key, etc.

Instsall zabbix-agent: 
```
sudo apt install zabbix-agent`
```
	
Set up `/etc/zabbix/zabbix_agentd.conf`:
		`Server=<server IP>`
		`ServerActive=<server IP>`	
		`Hostname=<host name defined on the server>`
		`TLSConnect=psk`
		`TLSAccept=psk`
		`TLSPSKIdentity=<identity>`
		`TLSPSKFile=<psk-key path>`

Store the key in `zabbix_agentd.psk` under the same directory.

[x] Dispatcher setup

```
pip install paho-mqtt zabbix_utils
```

Execute `dispatcher.py` with:

```
python dispatcher.py -a <server addr> \
	-i <psk identity> \
	-f <psk-key path, e.g., /etc/zabbix/zabbix_agentd.psk> \
	-n <Zabbix host name>
```

[x] Set up on-device systemd service files

	- monitoring.slice
  		- monitoring_{audit,coordinator}.service
	- detect_enforce.slice
  		- de_{sysfilter,login}.service
  		- camera_{streaming,control}.service
	- agent.slice
  		- zabbix-agent.service
  		- zabbix_dispatcher.service
	- system.slice
  		- dropbear.service # SSH server as a system service

removes symbolic link in `multi-user.target.wants/` to stop auto-run during boot:

```
systemctl disable zabbix-agent
```

set up auto-run during boot:

```
systemctl enable zabbix-agent
``` 

### Generate seccomp profiles for the apps

[x] Write profiling scripts

`rasmo/script/seccomp/profile_rpicamera.sh` as an example.

[x] Generate profiles

```
./seccomp_create -i <script path>
```

[x] Verify the correctness of each component & the connection with Zabbix server
	- Linux Audit
	- Mosquitto
	- Sysfilter
	- Login Filter
	- Seccomp supervisor
	- Camera streamer and controller
	- Zabbix agent & Dispatcher
	- Communication with the Zabbix server

### Clone SD card to other Raspberry Pis

This is a good [reference](https://www.dzombak.com/blog/2024/09/cloning-raspberry-pi-sd-cards/).

[x] Reassign SSH host keys

- openssh:

```sh
sudo rm /etc/ssh/ssh_host_*
sudo ssh-keygen -A
``` 

- dropbear:

Repeat key-generation steps above under `/etc/dropbear`

[x] Set IP address by `sudo nmcli`

[x] `sudo truncate -s 0 /etc/machine-id`

[x] Set hostname by `sudo raspi-config`

[x] Reconfigure all the RASMO settings on each machine

- Re-profile application modules
- Change host name in `zabbix_dispatcher.service`
- Set Gstreamer port in `camera_streaming.service` and profiling scripts. Devices need different port to stream videos to the same client.

[x] Set up Zabbix server hosts for the devices: clone existing one, set up IP address and PSK key

- Set up `zabbix_agentd.conf`: PSK identify, key file, Hostname

### NOTE

* Locale difference between CLI and system default may cause seccom_loader to report failed tokens
* Needs to redo profiling for the applications if device reboots
* In `mosquitto.conf`, `max_inflight_messages` defines quota for publishing messages from a client, if the quota is depleted, the clients may disconnect and reconnect.
Example from mosquitto log:

```
	1789881910: Bad socket read/write on client auto-6C9273B4-3B81-EBBE-C5F7-D041EA65659D: Quota exceeded
```
