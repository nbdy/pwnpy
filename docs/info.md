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
