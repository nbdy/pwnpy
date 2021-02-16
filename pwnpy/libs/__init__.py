from time import sleep

from runnable import Runnable
from podb import DB

from loguru import logger as log

from pwnpy.libs.Static import ExitCode, is_rpi, is_root


class Module(Runnable):
    name = "DefaultModule"
    db: DB = None
    shared_data = {}

    exit_reason = ""
    exit_code = ExitCode.NON_FATAL

    def __init__(self, name, mgr):
        Runnable.__init__(self)
        self.name = name
        self.mgr = mgr

    def error(self, code, reason):
        if code == ExitCode.NON_FATAL:
            lf = log.warning
        else:
            lf = log.error
        lf("Stopping '{}' because of '{}'.".format(self.name, reason))
        self.exit_code = code
        self.exit_reason = reason
        self.stop()

    @staticmethod
    def sleep(secs):
        sleep(secs)

    def save(self, data):
        self.mgr.db.upsert(data)

    def save_multiple(self, data):
        self.mgr.db.upsert_many(data)


__all__ = ['Module', 'ExitCode', 'Manager', 'is_rpi', 'is_root']
