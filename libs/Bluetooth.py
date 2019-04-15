from bluepy.btle import Scanner as btleScanner
from bluetooth import discover_devices

from libs import Scanner, Device


class BluetoothDevice(Device):
    device_type = "classic"
    name = None

    def __init__(self, address, name):
        Device.__init__(self, address)
        self.name = name

    @staticmethod
    def keys():
        return Device.keys() + ["name"]

    @staticmethod
    def dummy():
        return BluetoothDevice("FF:FF:FF:FF:FF:FF", "")


class BluetoothLEDevice(BluetoothDevice):
    device_type = "le"

    def __init__(self, address, name, **kwargs):
        BluetoothDevice.__init__(self, address, name)
        self._parse_kwargs(kwargs)


class Bluetooth(Scanner):
    name = "bluetooth"

    def scan_classic(self):
        print "doing classic scan"
        devs = discover_devices(duration=self.cfg["classicScanTime"], lookup_names=True)
        for addr, name in devs:
            self.db.update_bluetooth_device(BluetoothDevice(addr, name))  # todo read more

    def scan_btle(self):
        print "doing le scan"
        devs = btleScanner().scan(self.cfg["leScanTime"])
        for dev in devs:
            self.db.update_bluetooth_device(BluetoothLEDevice(dev.addr, ""))  # todo read more

    def _work(self):
        if self.cfg["onlyClassic"] or not self.cfg["onlyLE"]:
            self.scan_classic()
        if self.cfg["onlyLE"] or not self.cfg["onlyClassic"]:
            self.scan_btle()
