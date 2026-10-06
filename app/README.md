# PoC Apps

## `camera/`
The video streamer and camera controller (Flask server).

### Required packages 

libcamera-apps, gstreamer-1.0, libgstreamer

### How to stream video

Raspberry Pi CLI:

```
# cam-gst-bin: compiled gstreamer binary
rpicam-vid --width 640 --height 480 --framerate=60 --inline -n -t 0 -o - | ./{cam-gst-bin} <target IP address>
```

starts streaming 640x480 60 FPS videos to the `<target IP address>`.

## Dropbear SSH server

Patched Dropbear SSH server that generates `USER_AUTH` audit record with additional
authentication info such as the IP address, attempted username and the SSH fingerprint.

Example record:

```text
type=USER_AUTH msg=audit(1757153294.807:10833): pid=133282 uid=0
auid=1000 ses=6646 msg=’op=ssh−auth method=password valid_user=no
fingerprint=bf0091882be5c... acct=”baduser” exe=”/usr/sbin/dropbear”
hostname=linux addr=192.168.151.1 terminal=pts/1
res=failed ’UID=”root” AUID=”example”
```

Build with `-laudit`.




