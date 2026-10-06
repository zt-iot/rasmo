#!/bin/bash

# /usr/lib/systemd/system/camera_streaming.service

cur_dir=$(cd $(dirname ${BASH_SOURCE:-$0}) && pwd)

# start streaming
width=640
height=480
framerate=60

rpicam_bin=`which rpicam-vid`
gstreamer_bin=`which gst_camera`

profile_dir=${cur_dir}/../../output
target_ip="$1"
target_port="$2"

seccomp_loader -i ${profile_dir}/rpicam-vid -- ${rpicam_bin} --width ${width} --height ${height} --framerate=${framerate} --inline -n -t 0 -o - |\
seccomp_loader -i ${profile_dir}/gst_camera -- ${gstreamer_bin} ${target_ip} ${target_port}
#${rpicam_bin} --width ${width} --height ${height} --framerate=${framerate} --inline -n -t 0 -o - |\
#${gstreamer_bin} ${target_ip} ${target_port}
