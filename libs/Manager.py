from json import load
from time import sleep
from datetime import datetime
from importlib import import_module

from libs import T
from libs.GPS import GPS
from libs.Database import Database


class NoConfigurationSuppliedException(Exception):
    message = "i need a configuration"


class Manager(T):
    daemon = False
    cfg = None

    db = None
    gps = None

    modules = []
    running_modules = []

    reCounter = {}

    timestamp_start = None

    def __init__(self, cfg):
        T.__init__(self)
        self.cfg = load(open(cfg))["Manager"]
        self.do_run = True
        self.timestamp_start = datetime.now()
        self.db = Database(self.cfg["Database"])
        self.gps = GPS(self.db, self.cfg["GPS"])
        self._load_modules()

    def _load_modules(self):
        for k, v in self.cfg["modules"].items():
            self._log("loading module: '%s'" % k)
            self.modules.append(getattr(import_module("libs." + k), k))

    def _start_modules(self):
        for m in self.modules:
            self._log("starting module: '%s'" % m.__name__)
            self.running_modules.append(m(self.db, self.cfg["modules"][m.__name__]))

    def _stop_modules(self):
        for m in self.running_modules:
            m.stop()

    def _find_module(self, name):
        for m in self.modules:
            if m.name == name:
                return m
        return None

    def _on_run(self):
        self.gps.start()
        if self.cfg["waitForPosition"] and self.cfg["GPS"]["enable"]:
            while not self.gps.cP:
                self._log("waiting for gps")
                sleep(1)
        self._start_modules()

    def check_cleanshutd_pipe(self):
        if open(self.cfg["cleanshutdPipe"]).read() == '1':
            self.db.manager_run_insert(self.timestamp_start, datetime.now())
            self.stop()

    def _restart_modules(self):
        for m in self.running_modules:
            if not m.do_run:
                n = m.__name__
                self.running_modules.remove(m)
                if n is not None:
                    self._log("restarting: '%s'" % n)
                    self.running_modules.append(self._find_module(n)(self.db, self.cfg["modules"][n.__name__]))
                else:
                    self._log("could not restart '%s'" % n)

    def _work(self):
        if self.cfg["cleanshutdEnable"]:
            self.check_cleanshutd_pipe()
        self._restart_modules()
        sleep(self.cfg["sleepTime"])

    def _on_stop(self):
        self._stop_modules()
        self.stop()
