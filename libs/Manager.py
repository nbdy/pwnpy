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

    reCounter = {}

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
        if self.cfg["manager"]["waitForPosition"]:
            while not self.gps.cP:
                print "waiting for gps"
                sleep(1)
        self.wifi.start()
        self.bluetooth.start()

    def __restart_service(self, srv, name):
        if not self.cfg[name]["enable"]:
            return
        if name not in self.reCounter.keys():
            self.reCounter[name] = 0
        if not srv.do_run and self.cfg[name]["reCounterMax"] >= self.reCounter[name]:
            if name == "gps":
                self.gps = GPS(self.db, self.cfg[name])
            elif name == "wifi":
                self.wifi = WiFi(self.db, self.cfg[name])
            elif name == "bluetooth":
                self.bluetooth = Bluetooth(self.db, self.cfg[name])
            self.reCounter[name] += 1

    def _work(self):
        self.__restart_service(self.gps, "gps")
        self.__restart_service(self.wifi, "wifi")
        self.__restart_service(self.bluetooth, "bluetooth")
        sleep(self.cfg["manager"]["sleepTime"])

    def _on_stop(self):
        self.wifi.stop()
        self.bluetooth.stop()
        self.gps.stop()
