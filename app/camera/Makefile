.PHONY: all clean

SRC = camera-fdsrc.c
CFLAGS = -Wall -O2 $(shell pkg-config --cflags --libs gstreamer-1.0)
TARGET = gst_camera

$(TARGET): $(SRC)
	$(CC) $^ -o $@ $(CFLAGS)
	sudo mv $@ /usr/local/bin

clean:
	rm gst_camera
