from json import load
from time import sleep

from libs import T
from libs.Bluetooth import Bluetooth
from libs.Database import Database
from libs.GPS import GPS
from libs.WiFi import WiFi


class NoConfigurationSuppliedException(Exception):
    message = "i need a configuration"


class Manager(T):
    daemon = False
    name = "manager"
    cfg = None

    db = None
    gps = None
    wifi = None
    bluetooth = None

    gpsReCounter = 0
    btReCounter = 0
    wifiReCounter = 0

    def __init__(self, cfg):
        T.__init__(self)
        self.cfg = load(open(cfg))
        self.do_run = True

        self.db = Database(self.cfg["database"])
        self.gps = GPS(self.db, self.cfg["gps"])
        self.wifi = WiFi(self.db, self.cfg["wifi"])
        self.bluetooth = Bluetooth(self.db, self.cfg["bluetooth"])

    def _on_run(self):
        self.gps.start()
        self.wifi.start()
        self.bluetooth.start()

    def _work(self):
        if not self.gps.do_run and self.cfg["manager"]["gpsReCountMax"] >= self.gpsReCounter:
            self.gps = GPS(self.db, self.cfg["gps"])
            self.gpsReCounter += 1
        if not self.bluetooth.do_run and self.cfg["manager"]["btReCountMax"] >= self.gpsReCounter:
            self.bluetooth = Bluetooth(self.db, self.cfg["bluetooth"])
            self.btReCounter += 1
        if not self.wifi.do_run and self.cfg["manager"]["wifiReCountMax"] >= self.gpsReCounter:
            self.wifi = WiFi(self.db, self.cfg["wifi"])
            self.wifiReCounter += 1
        sleep(self.cfg["manager"]["sleepTime"])

    def _on_stop(self):
        self.wifi.stop()
        self.bluetooth.stop()
