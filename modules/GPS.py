from datetime import datetime
import gps

from libs import IThread


class Position(object):
    longitude = None
    latitude = None
    altitude = None
    speed = None
    time = None

    def __init__(self, data):
        self.longitude = data["lon"]
        self.latitude = data["lat"]
        self.altitude = data["alt"]
        self.speed = data["speed"]
        self.time = datetime.now()


class GPS(IThread):
    client = None
    cP = None

    def _on_run(self):
        self.client = gps.gps(mode=gps.WATCH_ENABLE | gps.WATCH_JSON)

    @staticmethod
    def _check_data(data, keys):
        for key in keys:
            if key not in data.keys():
                return False
        return True

    def _work(self):
        new_data = self.client.next()
        if self._check_data(new_data, ["lon", "lat", "alt", "speed"]):
            self.cP = Position(new_data)
            self.save(self.cP)
