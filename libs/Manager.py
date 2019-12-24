from json import load
from time import sleep
from datetime import datetime
from importlib import import_module

from libs import T
from libs.Database import Database


class NoConfigurationSuppliedException(Exception):
    message = "i need a configuration"


class Manager(T):
    daemon = False
    cfg = None
    name = "manager"

    db = None

    modules = []
    running_modules = []

    reCounter = {}

    timestamp_start = None

    def __init__(self, cfg):
        T.__init__(self)
        self.cfg = load(open(cfg))
        self.do_run = True
        self.timestamp_start = datetime.now()
        self.db = Database(self.cfg["Database"])
        self._load_modules()

    def _load_modules(self):
        for k, v in self.cfg["modules"].items():
            self.log_info("loading module: '%s'" % k)
            self.modules.append(getattr(import_module("modules." + k), k))

    def _start_modules(self):
        for m in self.modules:
            self.log_info("starting module: '%s'" % m.name)
            if m in self.cfg["modules"].keys():
                self.running_modules.append(m(self.db, self.cfg["modules"][m.name]))
            else:
                self.log_error("there was no config specified for '%s'." % m.name)

    def _stop_modules(self):
        for m in self.running_modules:
            m.stop()

    @staticmethod
    def _find_by_name(key, value, lst):
        for m in lst:
            if m.__dict__[key] == value:
                return m
        return None

    def _find_running_module(self, name):
        return self._find_by_name("name", name, self.running_modules)

    def _find_module(self, name):
        return self._find_by_name("name", name, self.modules)

    def _on_run(self):
        if self.cfg["waitForPosition"] and self.cfg["GPS"]["enable"]:
            gps = self._find_running_module("gps")
            while not gps.cP:
                self.log_debug("waiting for gps.")
                sleep(1)
        self._start_modules()

    def check_cleanshutd_pipe(self):
        if open(self.cfg["cleanshutdPipe"]).read() == '1':
            self.db.insert(self.name, {
                "start": self.timestamp_start,
                "end": datetime.now()
            })
            self.stop()

    def _restart_modules(self):
        for m in self.running_modules:
            if not m.do_run:
                n = m.__name__
                self.running_modules.remove(m)
                if n is not None:
                    self.log_info("restarting module: '%s'" % m.name)
                    self.running_modules.append(self._find_module(n)(self.db, self.cfg["modules"][n.__name__]))
                else:
                    self.log_error("could not restart module '%s'." % m.name)

    def _work(self):
        if self.cfg["cleanshutdEnable"]:
            self.check_cleanshutd_pipe()
        self._restart_modules()
        sleep(self.cfg["sleepTime"])

    def _on_stop(self):
        self._stop_modules()
        self.stop()
