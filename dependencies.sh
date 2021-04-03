#!/bin/bash

sudo apt-get install -y python3 python3-dev python3-pip python3-cython gpsd gpsd-clients libgps-dev \
                        libpcap-dev libopenjp2-tools aircrack-ng libbluetooth-dev libjpeg-dev \
                        libglib2.0-dev

if [ -f /sys/firmware/devicetree/base/model ] && [ "$1" == "-lipo" ]; then
  curl https://raw.githubusercontent.com/nbdy/clean-shutdown/master/setup.sh | bash
fi
