import sys
import ssl
#from sslpsk3 import SSLPSKContext
import json
import signal
import time
import argparse
import ipaddress
import paho.mqtt.client as mqtt
from zabbix_utils import Sender

# server IP address

def type_ip(addr):
	try:
		return ipaddress.ip_address(addr)
	except ValueError:
		raise argparse.ArgumentTypeError(f"Invalid IP address: {addr!r}")

def type_port(port):
	port_number = int(port)
	if not 0 < port_number < 65536:
		raise argparse.ArgumentTypeError(f"Invalid port number: {port}")
	return port_number

parser = argparse.ArgumentParser(description="Script for event forwarding to the Zabbix server")
parser.add_argument("-a", "--addr", type=type_ip, required=True, help="zabbix server address")
parser.add_argument("-p", "--port", type=type_port, default=10051, help="zabbix server port number")
parser.add_argument("-n", "--host", required=True, help="Target host name on zabbix server")
parser.add_argument("-i", "--psk-identity", required=True, help="PSK identity string")
parser.add_argument("-f", "--psk-file", required=True, help="PSK file path")

args = parser.parse_args()
server_ip = str(args.addr)
server_port = args.port
identity_str = args.psk_identity
host = args.host

try:
	with open(args.psk_file) as f:
		key_str = f.read().strip()
except OSError as e:
	parser.error(f"{args.psk_file}: {e.strerror}")

def psk_wrapper(sock, *args, **kargs):
	psk_identity = identity_str
	psk_key = bytes.fromhex(key_str)

#	context = SSLPSKContext(ssl.PROTOCOL_TLS_CLIENT)
	context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
	context.maximum_version = ssl.TLSVersion.TLSv1_2
	context.check_hostname = False
	context.verify_mode = ssl.CERT_NONE
	context.set_ciphers("PSK")
	# call back function to provide the identity and the key
	context.set_psk_client_callback(lambda hint: (psk_identity, psk_key))

	return context.wrap_socket(sock)
	

def finalize(signum, frame):
	mqtt_client.disconnect()

def on_message(client, userdata, msg):
	value = msg.payload.decode("utf-8", errors="replace").lower()
	topic = msg.topic
	
	if topic == topic_recv:
		key = key_recv
	elif topic == topic_ack:
		key = key_ack
	else:
		return

	response = sender.send_value(host, key, value)
	if json.loads(repr(response))["failed"] != 0:
		print(f"Failed to send data to zabbix",
			f"key: {key}",
			f"value: {value}", file=sys.stderr)

def on_connect(client, userdata, flags, rc, properties):
	if rc.is_failure:
		print(f"Failed to connect to MQTT broker with error {rc}")
		sys.exit(1)
	mqtt_client.subscribe([(topic_recv, 1), (topic_ack, 1)])
	print("connected to the MQTT Broker")

key_recv = "mqtt.login"
key_ack = "sync.cursor"

# include syscall anomaly here too

topic_recv = "global/cpsp/report/login"
topic_ack = "global/cpsp/sync-ack/login"

sender = Sender(server=server_ip, port=server_port, socket_wrapper=psk_wrapper)
mqtt_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)

# set MQTT callbacks
mqtt_client.on_message = on_message
mqtt_client.on_connect = on_connect

# set signal handlers
signal.signal(signal.SIGTERM, finalize)
signal.signal(signal.SIGINT, finalize)

mqtt_client.connect("localhost")
mqtt_client.loop_forever()
sys.exit(0)
