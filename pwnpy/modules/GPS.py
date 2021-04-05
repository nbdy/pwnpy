from pwnpy import Module, Manager
from pwnpy.libs import ModuleType, log
from time import sleep

import gpsd as gps


class GPS(Module):
    _g = None
    type = ModuleType.GPS

    def __init__(self, mgr: Manager):
        Module.__init__(self, "GPS", mgr)

    def on_start(self):
        try:
            self._g = gps.connect()
        except Exception as e:
            log.exception(e)

    def work(self):
        try:
            cp = gps.get_current()
            dcp = {
                "lat": cp.lat,
                "lng": cp.lon,
                "alt": cp.alt,
                "spd": cp.hspeed,
                "sat": cp.sats,
                "vsat": cp.sats_valid,
                "tme": cp.time,
                "clmb": cp.climb
            }
            self.shared_data = dcp
            # log.debug("Current position: {0}", dcp)
        except UserWarning as w:
            log.warning(w)
            pass
        sleep(1 / self.shared_data["spd"])
