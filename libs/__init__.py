from threading import Thread
from os import geteuid
from libs.Log import Log


class T(Thread):
    daemon = True
    do_run = False

    def __init__(self):
        Thread.__init__(self)

    def _work(self):
        pass

    def _on_run(self):
        self.log_info("running")

    def _on_end(self):
        self.log_info("stopped")

    def _on_stop(self):
        self.log_info("stopping")

    def log_debug(self, message):
        Log.d(self.name, message)

    def log_info(self, message):
        Log.i(self.name, message)

    def log_error(self, message):
        Log.e(self.name, message)

    def start(self):
        self.run()

    def run(self):
        self._on_run()
        while self.do_run:
            self._work()
        self._on_end()

    def stop(self):
        self._on_stop()
        self.do_run = False


class IThread(T):
    db = None
    cfg = None

    def __init__(self, db, cfg):
        T.__init__(self)
        self.db = db
        self.cfg = cfg
        self.name = cfg["name"]
        self.do_run = self.cfg["enable"]
        if self.cfg["root"]:
            self.do_run = geteuid() == 0
