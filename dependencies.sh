#!/bin/bash

sudo apt-get install -y python3 python3-dev python3-pip gpsd gpsd-clients libgps-dev python3-gps libopenjp2-tools aircrack-ng

if [ -f /sys/firmware/devicetree/base/model ]; then
  curl https://raw.githubusercontent.com/nbdy/clean-shutdown/master/setup.sh | bash
fi
