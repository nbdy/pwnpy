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
    \password
    \c pwnpi
    \i sql/bluetooth_classic.sql
    \i sql/bluetooth_le.sql
    \i sql/manager.sql
    \i sql/positions.sql
    \i sql/wifi.sql
    \q
    python install.py -ia
    vim config.json         # adjust values to your system
```