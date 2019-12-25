## pwnpy

[![Build Status](http://build.eberlein.io:8080/job/python_pwnpy/badge/icon)](http://build.eberlein.io:8080/job/python_pwnpy/)<br>

wardriving tool

### features:
- runs on any computer
- fully automatic
- [modular](https://github.com/smthnspcl/pwnpy/tree/master/modules)
- [LiPo SHIM](https://shop.pimoroni.com/products/lipo-shim) <br>
    - you might want to use [this](https://github.com/smthnspcl/clean-shutdown)
- [2.9 inch ePaper display](https://www.waveshare.com/wiki/2.9inch_e-Paper_Module)


### how to...
#### ...use it
```shell script
./pwn.py -c config.json
```

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