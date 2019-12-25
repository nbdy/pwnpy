from threading import Thread
from os import geteuid
from libs.Log import Log


class T(Thread):
    daemon = True
    do_run = False
    log = None

    def __init__(self, log):
        Thread.__init__(self)
        self.log = log

    def log_info(self, msg):
        self.log.i(self.name, msg)

    def log_debug(self, msg):
        self.log.d(self.name, msg)

    def log_error(self, msg):
        self.log.e(self.name, msg)

    def _work(self):
        pass

    def _on_run(self):
        self.log_info("running")

    def _on_end(self):
        self.log_info("stopped")

    def _on_stop(self):
        self.log_info("stopping")

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


class StopReasons(object):
    FATAL = 0
    RECOVERABLE = 1
    UNKNOWN = 2


class IThread(T):
    db = None
    cfg = None
    stop_reason = 1  # todo fix
    stop_message = "no reason"

    def __init__(self, name, db, log, cfg):
        T.__init__(self, log)
        self.name = name
        self.db = db
        self.cfg = cfg
        self.do_run = self.cfg["enable"]
        if self.cfg["root"]:
            self.do_run = geteuid() == 0
            if not self.do_run:
                self.stop_message = "insufficient permissions"
                self.stop_reason = StopReasons.FATAL

    def save(self, data):
        self.db.insert(self.name, data)

    def save_for(self, table, data):
        self.db.insert(table, data)

    def should_restart(self):
        r = self.stop_reason != StopReasons.FATAL
        self.log_debug("should restart: '%s'" % r)
        return r

    def stop_fatal(self, msg):
        self.log_error(msg)
        self.stop_message = msg
        self.stop_reason = StopReasons.FATAL
        self.stop()
