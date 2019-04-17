## pwnpy
wardriving tool written to run on a raspberry pi zero with the [LiPo SHIM](https://shop.pimoroni.com/products/lipo-shim). <br>

### captures:
```
- position
    - longitude
    - latitude
    - altidue
    - speed
    - time (universal primary key)

- bluetooth le
    - mac
    - name (useless, normally found in advertisements)
    - rssi
    - advertisements
    - connectable
    - positions (timestamp[] updated with time from position)
    
- bluetooth classic
    - mac
    - name
    - positions (as with ble)
```

### setup:
```
python install.py --help

usage: install.py {arguments}
{arguments}:
	-ia	--install-autostart
	-ua	--uninstall-autostart
	-d	--dependencies
	-db	--database
	--help
```

### usage:
```
vim config.json  # adjust values
python pwn.py /path/to/config.json
```

### todo:
```
- wifi stuff
```

### faq:
```
- Q: why?
- A: 
```