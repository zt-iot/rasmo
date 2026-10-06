#!/usr/bin/python

import argparse
import socket, time
import subprocess
import requests
import os, sys
import ipaddress

def type_ip(addr):
	try:
		return ipaddress.ip_address(addr)
	except ValueError:
		raise argparse.ArgumentTypeError(f"Invalid IP address: {addr!r}")

control_port = 5001

parser = argparse.ArgumentParser(description="Run the client workload")
parser.add_argument("-s", "--server", type=type_ip, required=True, help="Camera IP address")
parser.add_argument("-c", "--client", type=type_ip, required=True, help="Client IP")
parser.add_argument("-p", "--streaming-port", type=int, required=True, help="streaming port")

args = parser.parse_args()
server_ip = args.server
client_ip = args.client
streaming_port = args.streaming_port

try:
	ipaddress.ip_address(server_ip)
except ValueError:
	raise ValueError(f"Invalid server IP address {server_ip!r}")

tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

def start_stream():
	# on Linux
	#gst_str = f"gst-launch-1.0 udpsrc address={client_ip} port={streaming_port} caps=application/x-rtp ! queue ! rtph264depay ! h264parse ! v4l2h264dec ! fpsdisplaysink video-sink=autovideosink text-overlay=false sync=false"

	# on MacOS
	#gst_str = f"gst-launch-1.0 udpsrc address={client_ip} port={streaming_port} caps=application/x-rtp ! queue ! rtph264depay ! h264parse ! avdec_h264 ! fpsdisplaysink video-sink="glimagesink force-aspect-ratio=false" text-overlay=false sync=false
	gst_str = ["gst-launch-1.0", "udpsrc",\
		 f"address={client_ip}", f"port={streaming_port}",\
		 "caps=application/x-rtp", "!", "queue", "!", "rtph264depay", "!",\
		 "h264parse", "!", "avdec_h264", "!", "fpsdisplaysink",\
		 "video-sink=glimagesink force-aspect-ratio=false", "text-overlay=false", "sync=false", "-v"]
	return subprocess.Popen(gst_str, stdout=open(time.asctime().replace(' ', '-') + '_fps.txt', 'w'))

streamer = start_stream()

top_url = f"http://{server_ip}:{control_port}/"
info_url = top_url + "info"
reset_url = top_url + "reset/all"
zoom_url = top_url + "zoom"
focus_url = top_url + "focus"
pan_url = top_url + "pan"
tilt_url = top_url + "tilt"

# FIXME: ResetControl in server.py works incorrectly
# requests.put(reset_url, None)
zf_val = { 'value': 0 }
pt_val = { 'value': 90 }
cur_stat = requests.get(info_url).json()
#
if cur_stat['zoom'] != 0:
	requests.put(zoom_url, json=zf_val)
if cur_stat['focus'] != 0:
	requests.put(focus_url, json=zf_val)
if cur_stat['pan'] != 90:
	requests.put(pan_url, json=pt_val)
if cur_stat['tilt'] != 90:
	requests.put(tilt_url, json=pt_val)
#
time.sleep(2)
#
def fire_request(url, val):
	requests.put(url, json=val)
	time.sleep(0.025)

measure_start = time.perf_counter()

#for i in range(75): # 1s interval
for i in range(600): # 25ms interval
	fire_request(zoom_url, zf_val)
	fire_request(focus_url, zf_val)
	fire_request(pan_url, pt_val)
	fire_request(tilt_url, pt_val)

measure_end = time.perf_counter()

filename = time.asctime().replace(' ', '-') + '_time.txt'
with open(filename, 'w') as output_file:
	output = f"Elapsed time: {measure_end - measure_start} sec"
	output_file.write(output)

streamer.terminate()
streamer.wait(60)
