import psycopg2


class Database(object):
    cn = None
    cfg = None

    def _build_connection_string(self):
        r = "dbname='"
        r += self.cfg["database"]
        r += "' user='"
        r += self.cfg["user"]
        r += "' host='"
        r += self.cfg["host"]
        r += "' password='"
        r += self.cfg["password"]
        r += "'"
        return r

    def __init__(self, cfg):
        self.cfg = cfg
        self.cn = psycopg2.connect(self._build_connection_string())

    query_position_insert = """INSERT INTO positions (longitude, latitude, altitude, speed, time, satellites_used, 
    satellites) VALUES ('%s', '%s', '%s', '%s', '%s', '%s', '%s');"""

    def update_position(self, position):
        cr = self.cn.cursor()
        tmp = self.query_position_insert % (
        position.longitude, position.latitude, position.altitude, position.speed, position.time,
        position.satellites_used, position.satellites)
        cr.execute(tmp)
        cr.close()

    query_position_get_newest = """SELECT * FROM positions ORDER BY greatest(time) DESC LIMIT 1;"""

    def get_newest_position(self):
        cr = self.cn.cursor()
        cr.execute(self.query_position_get_newest)
        tmp = self.cr.fetchall()
        cr.close()
        return tmp[0]

    query_wifi_device_update = """INSERT INTO wifi (device_type, channel, encryption, communication_partners, essid) 
    VALUES ('%s', '%s', '%s', '%s', '%s', '%s');"""

    def update_wifi_device(self, device):
        cr = self.cn.cursor()
        tmp = self.query_wifi_device_update % (device.device_type, device.channel, device.encryption,
                                               device.communication_partners, device.essid)
        cr.execute(tmp)
        cr.close()

    query_bluetooth_device_update = """INSERT INTO bluetooth (address, name, device_type) VALUES ('%s', '%s', '%s');"""

    def update_bluetooth_device(self, device):
        cr = self.cn.cursor()
        tmp = self.query_bluetooth_device_update % (device.address, device.name, device.device_type)
        cr.execute(tmp)
        cr.close()
