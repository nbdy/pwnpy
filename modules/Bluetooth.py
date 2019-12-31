from pybt import ClassicDevice, LEDevice, Beacon
from libs import IThread


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


class Bluetooth(IThread):
    def scan_classic(self):
        for d in ClassicDevice.scan(self.cfg["classicScanTime"]):
            self.save_for("bluetoothClassic", d)

    def scan_btle(self):
        for d in LEDevice.scan(self.cfg["leScanTime"], self.cfg["leReadAll"]):
            self.save_for("bluetoothLE", d)

    def scan_beacon(self):
        for d in Beacon.scan():
            self.save_for("bluetoothBeacon", d)

    def _work(self):
        if self.cfg["scanClassic"]:
            self.scan_classic()
        if self.cfg["scanLE"]:
            self.scan_btle()
        if self.cfg["scanBeacon"]:
            self.scan_beacon()
