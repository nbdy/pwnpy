#!/bin/bash

sudo apt-get install -y python3 python3-dev python3-pip gpsd gpsd-clients libgps-dev libopenjp2-tools aircrack-ng libbluetooth-dev

if [ -f /sys/firmware/devicetree/base/model ] && [ "$1" == "-lipo" ]; then
  curl https://raw.githubusercontent.com/nbdy/clean-shutdown/master/setup.sh | bash
fi
