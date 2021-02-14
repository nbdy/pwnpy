from time import sleep
from datetime import datetime
from loguru import logger as log
from os import listdir
from runnable import Runnable
from podb import DB
import pyclsload
from os.path import isfile


class NoConfigurationSuppliedException(Exception):
    message = "No configuration has been supplied."


class Manager(Runnable):
    cfg: dict = None
    db: DB = None

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
        self.db = DB(cfg["db"])
        self._load_modules(cfg["module-path"], cfg["modules"])

    def _load_modules(self, module_path: str, modules: list[str]):
        log.debug("Loading modules from: {}", module_path)
        for m in listdir(module_path):
            for w in modules:
                if w in m:
                    log.info("Loading module: '{}'", m)
                    self.modules.append(pyclsload.load(m, w, *[self.shared_data]))

    def _start_modules(self):
        for m in self.modules:
            m.start()

    def _stop_modules(self):
        for m in self.modules:
            m.stop()

    def on_start(self):
        self._start_modules()

    def on_stop(self):
        self._stop_modules()

    def check_cleanshutd_pipe(self):
        if open("/tmp/cleanshutd").read() == '1':  # todo configurable
            self.db.insert(self.name, {
                "start": self.timestamp_start,
                "end": datetime.now()
            })
            self.stop()

    def accumulate_shared_data(self):
        for m in self.modules:
            self.shared_data[m.name] = m.shared_data

    def _work(self):
        if isfile("/sys/firmware/devicetree/base/model"):
            self.check_cleanshutd_pipe()
        self.accumulate_shared_data()
        sleep(0.1)
