#!/bin/bash

# /usr/lib/systemd/system/camera_streaming.service

cur_dir=$(cd $(dirname ${BASH_SOURCE:-$0}) && pwd)
#tracee_path=$(readlink -f `which libcamera-vid`)
#tracee_name="${tracee_path##*/}"
tracee_name="rpicam-vid"
strace_dir="$1/${tracee_name}/strace"

# create folder: if it exists, reset
if [ ! -d "${strace_dir}" ]; then
	mkdir -p ${strace_dir}
else
	rm -rf ${strace_dir}/*
fi

# start streaming
width=640
height=480
framerate=60

strace_bin=`which strace`
strace_options="-v -qq -s 0 -ff --output=${strace_dir}/${tracee_name} -n --raw=ioctl"

tracee_cmd="${tracee_name} --width ${width} --height ${height} --framerate=${framerate} --inline -n -t 0 -o -"

echo "Tracee: ${tracee_cmd}"

# Libcamera
timeout -s SIGINT 10 ${strace_bin} ${strace_options} ${tracee_cmd} | `which gst_camera` localhost &> /dev/null
