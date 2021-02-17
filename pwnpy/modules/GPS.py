from pwnpy import Module
from podb import DB
from time import sleep

from gps import gps, WATCH_ENABLE


class GPS(Module):
    _g: gps = None

    def __init__(self, db: DB):
        Module.__init__(self, "GPS", db)

    def on_start(self):
        self._g = gps(mode=WATCH_ENABLE)

    def work(self):
        self._g.next()
        self.shared_data = {
            "lat": self._g.fix.latitude,
            "lng": self._g.fix.longitude,
            "alt": self._g.fix.altitude,
            "spd": self._g.fix.speed,
            "sat": self._g.satellites_used
        }
        sleep(0.5)
