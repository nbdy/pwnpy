from pwnpy import Module, Manager
from time import sleep

from gps import gps, WATCH_ENABLE, GPSD_PORT


class GPS(Module):
    _g: gps = None

    def __init__(self, mgr: Manager):
        Module.__init__(self, "GPS", mgr)

    def on_start(self):
        self._g = gps("127.0.0.1", GPSD_PORT, mode=WATCH_ENABLE)

    def work(self):
        self._g.next()
        self.shared_data = {
            "lat": self._g.fix.latitude,
            "lng": self._g.fix.longitude,
            "alt": self._g.fix.altitude,
            "spd": self._g.fix.speed,
            "sat": self._g.satellites_used,
            "tme": self._g.fix.time
        }
        sleep(0.5)
