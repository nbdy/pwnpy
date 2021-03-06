from time import sleep
from datetime import datetime
from loguru import logger as log
from os import listdir, path
from runnable import Runnable
import dataset
import pyclsload
from os.path import isfile

from typing import List
from pwnpy.libs import ExitCode, ModuleType


class NoConfigurationSuppliedException(Exception):
    message = "No configuration has been supplied."


class Manager(Runnable):
    cfg: dict = None
    db = None

    shared_data = {}

    modules: list = []

    timestamp_start: datetime = None
    timestamp_loaded: datetime = None

    def __init__(self, cfg: dict):
        Runnable.__init__(self)
        if cfg is None:
            raise NoConfigurationSuppliedException
        log.debug(cfg)
        self.timestamp_start = datetime.now()
        self.db = dataset.connect("sqlite:///{0}".format(cfg["db"]))
        self.cfg = cfg
        self._load_modules(cfg["module-path"], cfg["modules"], cfg["w"], cfg["bt"])

    def _load_modules(self, module_path: str, modules: List[str], wifi: bool, bt: bool):
        log.debug("Searching for modules '{}' in directory {}", ', '.join(modules), module_path)
        if not path.isdir(module_path):
            log.error("Module directory '{}' does not exist.", module_path)
            return self.stop()
        mods = []
        for m in listdir(module_path):
            if m.endswith(".py") or m.endswith(".pyc"):
                mods.append(m)
        if len(mods) == 0:
            log.error("No modules to load, nothing to do.")
            return self.stop()
        log.debug("Trying to load {0} of {1} modules.", len(modules), len(mods))
        for m in mods:
            for w in modules:
                if w.lower() == m.lower()[0:-3]:
                    log.info("Loading module: '{}'", m)
                    mod = pyclsload.load(path.join(module_path, m), w, *[self])
                    if mod.type == ModuleType.WIFI and not wifi:
                        continue
                    elif mod.type == ModuleType.BT and not bt:
                        continue
                    else:
                        self.modules.append(mod)
        if len(self.modules) < len(modules):
            log.warning("Only loaded {0} of {1} modules.", len(self.modules), len(modules))
            log.warning("Could not load the following modules:")
            for m in self.modules:
                modules.remove(m.name)
            for m in modules:
                log.warning("\t- {0}", m)
        log.debug("Loaded requested modules.")

    def _start_modules(self):
        for m in self.modules:
            log.info("Starting module '{}'", m.name)
            m.start()

    def _stop_modules(self):
        for m in self.modules:
            log.info("Stopping module '{}'", m.name)
            m.stop()

    def on_start(self):
        self._start_modules()

    def on_stop(self):
        self._stop_modules()

    def check_cleanshutd_pipe(self):
        if isfile("/tmp/cleanshutd"):
            if open("/tmp/cleanshutd").read() == '1':  # todo configurable
                self.db.insert(self.name, {
                    "start": self.timestamp_start,
                    "end": datetime.now()
                })
                self.stop()

    def accumulate_shared_data(self):
        for m in self.modules:
            if m.shared_data is not None and m.shared_data != {}:
                self.shared_data[m.name] = m.shared_data

    def check_modules(self):
        for m in self.modules:
            if not m.do_run and m.exit_code == ExitCode.NON_FATAL:
                m.start()

    def work(self):
        try:
            if isfile("/sys/firmware/devicetree/base/model"):
                self.check_cleanshutd_pipe()
            self.accumulate_shared_data()
            sleep(0.1)
        except KeyboardInterrupt:
            self.stop()

    def get_loaded_module_names(self):
        r = []
        for m in self.modules:
            r.append(m.name)
        return r

    def get_module_shared_data(self, name):
        if name in self.shared_data.keys():
            return self.shared_data[name]
        return None

    def get_shared_data_id(self, name):
        m = self.get_module_shared_data(name)
        if m is not None:
            return m["id"]
        return None

    def get_shared_data_data(self, name):
        m = self.get_module_shared_data(name)
        if m is not None:
            return m["data"]
        return None
