## pwnpy

wardriving tool

### features:
- fully automatic
- [modular](https://github.com/nbdy/pwnpy/tree/master/modules)
- [LiPo SHIM](https://shop.pimoroni.com/products/lipo-shim) <br>
    - you might want to use [this](https://github.com/nbdy/clean-shutdown)
- [2.13 inch ePaper display](https://www.waveshare.com/wiki/2.13inch_e-Paper_HAT_(B))

### modules:
- [X] Bluetooth
  - [X] LE
  - [X] Classic
- [X] GPS
- [X] EPaperUI
- [X] WiFi
- [ ] WebUI
### show and tell
[![asciicast](https://asciinema.org/a/299821.svg)](https://asciinema.org/a/299821)
### how to...
#### .. install
```shell
pip3 install pwnpy
```
#### ...use it
```shell script
pwnpy -c config.json
```

#### ... use the WiFi module without root
```shell
# set capabilities for our python executable
setcap cap_net_raw=eip /usr/bin/python3
```

#### ... use the BT module without root
```shell
# add the pi user to the bluetooth group and reboot
sudo usermod -a -G bluetooth pi ; reboot
```