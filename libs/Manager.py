from json import load
from time import sleep
from datetime import datetime
from importlib import import_module

from libs import T
from libs.Database import Database
from libs.Log import Log


class NoConfigurationSuppliedException(Exception):
    message = "i need a configuration"


class Manager(T):
    daemon = False
    cfg = None
    log = None
    db = None

    modules = []
    running_modules = []

    timestamp_start = None

    def __init__(self, cfg):
        if cfg is None:
            raise NoConfigurationSuppliedException
        self.cfg = load(open(cfg))
        T.__init__(self, Log(self.cfg["Log"]))
        self.do_run = True
        self.name = "Manager"
        self.timestamp_start = datetime.now()
        self.db = Database(self.cfg["Database"])
        self._load_modules()

    def _load_modules(self):
        for k, v in self.cfg["modules"].items():
            if v["enable"]:
                self.log_info("loading module: '%s'" % k)
                self.modules.append(getattr(import_module("modules." + k), k))
            else:
                self.log_debug("disabled module: '%s'" % k)

    def _start_modules(self):
        for k in self.cfg["modules"].keys():
            if self.cfg["modules"][k]["enable"]:
                self.log_info("starting module: '%s'" % k)
                self.running_modules.append(self._find_instantiate(k))

    def _stop_modules(self):
        for m in self.running_modules:
            m.stop()

    @staticmethod
    def _find_by_name(value, lst):
        for m in lst:
            if m.__name__ == value:
                return m
        return None

    def _find_running_module(self, name):
        return self._find_by_name(name, self.running_modules)

    def _find_module(self, name):
        return self._find_by_name(name, self.modules)

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

    def _find_instantiate(self, name):
        return self._find_module(name)(name, self.db, self.log, self.cfg["modules"][name])

    def _restart_modules(self):
        if len(self.modules) == 0:
            self.log_error("no modules are loaded anymore")
            self.log_info("exiting")
            self.stop()

        for m in self.running_modules:
            self.log_debug("'%s' is running? '%s'" % (m.name, m.do_run))
            if not m.do_run:
                self.log_debug("'%s' has been stopped because of '%s'" % (m.name, m.stop_message))
                self.log_debug("'%s' stop reason was '%i'" % (m.name, m.stop_reason))
                if m.should_restart():
                    n = m.name
                    self.running_modules.remove(m)
                    if n is not None:
                        self.log_info("restarting module: '%s'" % n)
                        self.running_modules.append(self._find_instantiate(n))
                    else:
                        self.log_error("could not restart module '%s'." % m.name)
                else:
                    self.log_error("not restarting module '%s' because of '%s'" % (m.name, m.stop_message))
                    self.modules.remove(m.__class__)
                    self.running_modules.remove(m)
                    self.log_info("removed module '%s'" % m.name)

    def _work(self):
        if self.cfg["cleanshutdEnable"]:
            self.check_cleanshutd_pipe()
        self._restart_modules()
        try:
            sleep(self.cfg["sleepTime"])
        except KeyboardInterrupt:
            self.stop()

    def _on_stop(self):
        self._stop_modules()
