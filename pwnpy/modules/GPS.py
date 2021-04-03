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
            self.shared_data = {
                "lat": cp.lat,
                "lng": cp.lon,
                "alt": cp.alt,
                "spd": cp.hspeed,
                "sat": cp.sats,
                "vsat": cp.sats_valid,
                "tme": cp.time,
                "clmb": cp.climb
            }
            # log.debug("Current position: {0}", self.shared_data)
        except UserWarning as w:
            log.warning(w)
            pass
        sleep(0.1)  # TODO(nbdy): adjust by current speed
