from bluepy.btle import Scanner as btleScanner
from bluetooth import discover_devices

from libs import Scanner


class BluetoothDevice(object):
    address = None
    name = None

    def __init__(self, address, name):
        self.address = address
        self.name = name

    @staticmethod
    def dummy():
        return BluetoothDevice("FF:FF:FF:FF:FF:FF", "")


class BluetoothLEDevice(BluetoothDevice):
    rssi = None
    connectable = None
    advertisements = []

    def __init__(self, address, name, rssi, connectable):
        BluetoothDevice.__init__(self, address, name)
        self.rssi = rssi
        self.connectable = connectable


class Bluetooth(Scanner):
    name = "bluetooth"

    def scan_classic(self):
        print "doing classic scan"
        devs = discover_devices(duration=self.cfg["classicScanTime"], lookup_names=True)
        for addr, name in devs:
            self.db.bluetooth_classic_device_insert(BluetoothDevice(addr, name))  # todo read more

    def scan_btle(self):
        print "doing le scan"
        devs = btleScanner().scan(self.cfg["leScanTime"])
        for dev in devs:
            d = BluetoothLEDevice(dev.addr, "", dev.rssi, dev.connectable)  # todo read more
            for adtype, desc, val in dev.getScanData():
                d.advertisements.append({
                    "type": adtype,
                    "desc": desc,
                    "value": val
                })
            self.db.bluetooth_le_device_insert(d)

    def _work(self):
        if self.cfg["onlyClassic"] or not self.cfg["onlyLE"]:
            self.scan_classic()
        if self.cfg["onlyLE"] or not self.cfg["onlyClassic"]:
            self.scan_btle()
