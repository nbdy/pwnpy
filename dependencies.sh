#!/bin/bash

echo "Installing apt dependencies"
sudo apt-get install -y python3 python3-dev python3-pip cython3 gpsd gpsd-clients libgps-dev \
                        libpcap-dev libopenjp2-tools aircrack-ng libbluetooth-dev libjpeg-dev \
                        libglib2.0-dev

if [ -f /sys/firmware/devicetree/base/model ] && [ "$1" == "-lipo" ]; then
  echo "Running on rpi and -lipo switch was specified."
  echo "Installing clean-shutdown script."
  curl https://raw.githubusercontent.com/nbdy/clean-shutdown/master/setup.sh | bash
fi

if [ ! -f /usr/bin/mongo ]; then
  echo "Installing MongoDB since it is not already installed."
  wget -qO - https://www.mongodb.org/static/pgp/server-4.4.asc | sudo apt-key add -
  echo "deb [ arch=arm64 ] https://repo.mongodb.org/apt/ubuntu focal/mongodb-org/4.4 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-4.4.list
  sudo apt-get update
  sudo apt-get install -y mongodb-org
fi

echo "Installer script has finished."