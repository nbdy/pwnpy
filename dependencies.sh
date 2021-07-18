#!/bin/bash

echo "Installing apt dependencies"
sudo apt-get update
sudo apt-get upgrade -y
sudo apt-get install -y python3 python3-dev python3-pip cython3 gpsd gpsd-clients libgps-dev \
                        libpcap-dev libopenjp2-tools aircrack-ng libbluetooth-dev libjpeg-dev \
                        libglib2.0-dev git

pip3 install -r requirements.txt --upgrade

if [ -f /sys/firmware/devicetree/base/model ]; then
  sudo apt install -y python3-rpi.gpio
fi

if [ -f /sys/firmware/devicetree/base/model ] && [ "$1" == "-lipo" ]; then
  echo "Running on rpi and -lipo switch was specified."
  echo "Installing clean-shutdown script."
  curl https://raw.githubusercontent.com/nbdy/clean-shutdown/master/setup.sh | bash
fi

echo "Installer script has finished."
