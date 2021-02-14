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
        self.shared_data = self._g.next()
        sleep(0.5)
