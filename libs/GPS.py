from time import sleep
from uuid import uuid4

import gps

from libs import Scanner, DBObject


class Position(DBObject):
    longitude = None
    latitude = None
    altitude = None
    speed = None
    satellites = None
    satellites_used = None
    time = None

    def __init__(self, client):
        DBObject.__init__(self, uuid=uuid4())  # todo generate uuid from lng,lat,alt
        self.longitude = client.fix.longitude
        self.latitude = client.fix.latitude
        self.altitude = client.fix.altitude
        self.speed = client.fix.speed
        self.time = client.fix.time
        self.satellites_used = client.fix.satellites_used
        self.satellites = client.fix.satellites


class GPS(Scanner):
    name = "gps"

    position_id = None
    position = None
    client = None

    def __init__(self, db, cfg):
        Scanner.__init__(self, db, cfg)
        self.client = gps.gps()

    def _work(self):
        self.position = Position(self.client)
        self.position_id = self.position.uuid
        sleep(self.cfg["sleepTime"])
