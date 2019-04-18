from json import load
from time import sleep
from datetime import datetime

from libs import T
from libs.Bluetooth import Bluetooth
from libs.Database import Database
from libs.GPS import GPS
from libs.WiFi import WiFi
from libs.Server import Server


class NoConfigurationSuppliedException(Exception):
    message = "i need a configuration"


class Manager(T):
    daemon = False
    name = "manager"
    cfg = None

    db = None
    gps = None
    wifi = None
    server = None
    bluetooth = None

    reCounter = {}

    timestamp_start = None

    def __init__(self, cfg):
        T.__init__(self)
        self.cfg = load(open(cfg))
        self.do_run = True
        self.timestamp_start = datetime.now()  # todo insert start and stop timestamp into database upon shutdown

        self.db = Database(self.cfg["database"])
        self.gps = GPS(self.db, self.cfg["gps"])
        self.wifi = WiFi(self.db, self.cfg["wifi"])
        self.server = Server(self.db, self.cfg["server"])
        self.bluetooth = Bluetooth(self.db, self.cfg["bluetooth"])

    def _on_run(self):
        self.server.start()
        self.gps.start()
        if self.cfg["manager"]["waitForPosition"] and self.cfg["gps"]["enable"]:
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

    def check_cleanshutd_pipe(self):
        if open(self.cfg["manager"]["cleanshutdPipe"]).read() == '1':
            self.db.manager_run_insert(self.timestamp_start, datetime.now())
            self.stop()

    def _work(self):
        if self.cfg["manager"]["cleanshutdEnable"]:
            self.check_cleanshutd_pipe()
        self.__restart_service(self.gps, "gps")
        self.__restart_service(self.wifi, "wifi")
        self.__restart_service(self.bluetooth, "bluetooth")
        sleep(self.cfg["manager"]["sleepTime"])

    def _on_stop(self):
        self.server.stop()
        self.wifi.stop()
        self.bluetooth.stop()
        self.gps.stop()
