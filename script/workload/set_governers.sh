#!/bin/bash

# set CPU0 will set all four CPUs because they share one clock domain
echo performance | sudo tee /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor
