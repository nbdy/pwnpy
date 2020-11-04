## pwnpy
[![Build Status](https://build.eberlein.io/buildStatus/icon?job=python_pwnpy)](https://build.eberlein.io/job/python_pwnpy/)

wardriving tool

### features:
- runs on any computer
- fully automatic
- [modular](https://github.com/nbdy/pwnpy/tree/master/modules)
- [LiPo SHIM](https://shop.pimoroni.com/products/lipo-shim) <br>
    - you might want to use [this](https://github.com/nbdy/clean-shutdown)
- [2.9 inch ePaper display](https://www.waveshare.com/wiki/2.9inch_e-Paper_Module)

### show and tell
[![asciicast](https://asciinema.org/a/299821.svg)](https://asciinema.org/a/299821)
### how to...
#### ...use it
```shell script
./pwn.py -c config.json
```

#### ...install dependencies
```
pip3 install --upgrade -r requirements.txt
```
the bluetooth module depends on [pybt](https://github.com/nbdy/pybt)<br>
most likely there will be issues with installing gattlib<br>
follow the instructions in the pybt repo

#### ...install it
```shell script
usage: ./install.py {arguments}
{arguments}:
	-ia	--install-autostart
	-ua	--uninstall-autostart
	-d	--dependencies
	-db	--database
	--help
```
