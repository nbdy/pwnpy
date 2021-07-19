from time import sleep
from uuid import uuid4
from datetime import datetime

from runnable import Runnable
from loguru import logger as log

from pwnpy.libs.Static import ExitCode, is_rpi, is_root


class ModuleType:
    NONE = 0
    WIFI = 1
    BT = 2
    GPS = 3
    UI = 4


class Module(Runnable):
    name = "DefaultModule"
    shared_data = {
        "id": None,  # holds the uuid of the last inserted value so only a reference can be saved
        "data": {}  # holds the actual data to be shared with other modules
    }
    type = ModuleType.NONE

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
        self.shared_data["exit_code"] = code
        self.shared_data["exit_reason"] = reason
        self.stop()

    @staticmethod
    def sleep(secs):
        sleep(secs)

    def save(self, data: dict):
        u = str(uuid4())
        data.update({"_uuid": u})
        for k, v in data.items():
            if isinstance(v, datetime):
                data[k] = v.strftime("%Y%m%d%H%M%S")
        log.debug("Inserting: {}", data)
        self.mgr.db[self.name].insert(data)
        return u


__all__ = ['Module', 'ExitCode', 'Manager', 'is_rpi', 'is_root', 'log', 'ModuleType']
