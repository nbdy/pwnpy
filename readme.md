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
 
- wifi
    - address
    - device type (sta or ap)
    - encryption type (none, wep, wpa, wpa2, radius)
    - channel 
    - communication partners
    - essid (if ap)
    - positions (as with ble)
    - rates
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
	
e.g.: 
    python install.py -d -db
    sudo -u postgres psql
    CREATE DATABASE pwnpi;
    \q
    python install.py -ia 
```

you might also want to use [this](https://github.com/smthnspcl/clean-shutdown). <br>
this way we can tell pwnpy to stop and save start and stop timestamps

### usage:
```
vim config.json  # adjust values
python pwn.py /path/to/config.json
```

### todo:
```
- device timeline
- intrusive stuff
```

### faq:
- Q: why?
- A: 

+ Q: is there a case for this?
+ A: [yop](https://github.com/smthnspcl/pwnpi-case)
