import psycopg2
from json import dumps, loads


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

    def _execute(self, query, commit=False, fetchone=False, fetchall=False):
        r = None
        cr = self.cn.cursor()
        cr.execute(query)
        if fetchall:
            r = cr.fetchall()
        if fetchone:
            r = cr.fetchone()
        if commit:
            self.cn.commit()
        cr.close()
        return r

    @staticmethod
    def _check_table_valid(table):
        return table in ["bluetooth_classic", "bluetooth_le", "manager", "positions", "wifi"]

    query_position_insert = """INSERT INTO positions (longitude, latitude, altitude, speed, time) VALUES 
    ('%s', '%s', '%s', '%s', '%s');"""

    def update_position(self, position):
        self._execute(self.query_position_insert % (position.longitude, position.latitude, position.altitude,
                                                    position.speed, position.time), True)

    query_position_get_newest = """SELECT * FROM positions ORDER BY time DESC LIMIT 1;"""

    def get_newest_position_timestamp(self):
        return self._execute(self.query_position_get_newest, fetchall=True)[-1][-1]

    query_bluetooth_classic_device_exists = """SELECT EXISTS(SELECT 1 FROM bluetooth_classic WHERE address = '%s');"""

    def bluetooth_classic_device_exists(self, address):
        return self._execute(self.query_bluetooth_classic_device_exists % address, fetchall=True)[0][0]

    query_bluetooth_classic_device_update = """UPDATE bluetooth_classic SET positions = array_append(positions, '%s') 
    WHERE address = '%s';"""

    def bluetooth_classic_device_update(self, device):
        self._execute(self.query_bluetooth_classic_device_update %
                      (self.get_newest_position_timestamp(), device.address), True)

    query_bluetooth_classic_device_insert = """INSERT INTO bluetooth_classic (address, name, positions) 
    VALUES ('%s', '%s', '{%s}');"""

    def bluetooth_classic_device_insert(self, device):
        if self.bluetooth_classic_device_exists(device.address):
            self.bluetooth_classic_device_update(device)
        else:
            self._execute(
                self.query_bluetooth_classic_device_insert % (device.address, device.name,
                                                              self.get_newest_position_timestamp()), True)

    query_bluetooth_le_device_exists = """SELECT EXISTS(SELECT 1 FROM bluetooth_le WHERE address = '%s');"""

    def bluetooth_le_device_exists(self, address):
        return self._execute(self.query_bluetooth_le_device_exists % address, fetchall=True)[0][0]

    query_bluetooth_le_device_update = """UPDATE bluetooth_le SET positions = array_append(positions, '%s') 
    WHERE address = '%s';"""

    def bluetooth_le_device_update(self, device):
        self._execute(self.query_bluetooth_le_device_update % (self.get_newest_position_timestamp(), device.address),
                      True)

    query_bluetooth_le_device_insert = """INSERT INTO bluetooth_le (address, name, positions, rssi, connectable, 
    advertisements) VALUES ('%s', '%s', '{%s}', '%s', '%s', '%s');"""

    def bluetooth_le_device_insert(self, device):
        device.advertisements = dumps(device.advertisements)
        if self.bluetooth_le_device_exists(device.address):
            self.bluetooth_le_device_update(device)
        else:
            self._execute(
                self.query_bluetooth_le_device_insert % (device.address, device.name,
                                                         self.get_newest_position_timestamp(), device.rssi,
                                                         device.connectable, device.advertisements), True)

    query_bluetooth_le_device_get = """SELECT * FROM bluetooth_le WHERE address = '%s';"""

    def bluetooth_le_device_get(self, address):
        self._execute(self.query_bluetooth_le_device_get % address, True)

    query_wifi_device_update = """UPDATE wifi SET positions = array_append(positions, '%s'), 
    communication_partners = array_append(communication_partners, '%s') WHERE address = '%s';"""

    def wifi_device_update(self, device):
        r = self._execute("SELECT COUNT(1) FROM wifi WHERE address = '%s' AND communication_partners @> '{%s}';" % (
                          device.address, device.communication_partner))[0][0]
        if r != 0L:
            tmp = "UPDATE wifi SET positions = array_append(positions, '%s') WHERE address='%s'" % (
                self.get_newest_position_timestamp(), device.address)
        else:
            tmp = self.query_wifi_device_update % (self.get_newest_position_timestamp(), device.communication_partner,
                                                   device.address)
        self._execute(tmp, True)

    query_wifi_device_exists = """SELECT EXISTS(SELECT 1 FROM wifi WHERE address = '%s');"""

    def wifi_device_exists(self, address):
        return self._execute(self.query_wifi_device_exists % address, False, True)[0][0]

    query_wifi_device_insert = """INSERT INTO wifi (address, device_type, channel, encryption, communication_partners, 
    essid, positions, rates) VALUES ('%s', '%s', '%s', '%s', '{%s}', '%s', '{%s}', '%s')"""

    def wifi_device_insert(self, device):
        if self.wifi_device_exists(device.address):
            self.wifi_device_update(device)
        else:
            self._execute(
                self.query_wifi_device_insert % (device.address, device.device_type, device.channel,
                                                 device.encryption, device.communication_partner, device.essid,
                                                 self.get_newest_position_timestamp(), device.rates), True)

    query_manager_run_insert = """INSERT INTO manager (start, "end") VALUES ('%s', '%s')"""

    def manager_run_insert(self, start, end):
        self._execute(self.query_manager_run_insert % (start, end), True)

    query_get_count = """SELECT COUNT(*) FROM %s;"""

    def get_count(self, table):
        if not self._check_table_valid(table):
            return -1
        return int(self._execute(self.query_get_count % table, fetchone=True)[0])

    query_get_all = """SELECT * FROM %s;"""

    def get_all(self, table):
        if not self._check_table_valid(table):
            return []
        return self._execute(self.query_get_all % table, False, True)

    def get_column_names(self, table):
        if not self._check_table_valid(table):
            return []
        if table == "bluetooth_classic":
            return ["address", "name", "positions"]
        elif table == "bluetooth_le":
            return ["address", "name", "positions", "rssi", "connectable", "advertisements"]
        elif table == "manager":
            return ["id", "start", "end"]
        elif table == "positions":
            return ["longitude", "latitude", "altitude", "speed", "time"]
        elif table == "wifi":
            return ["address", "device_type", "channel", "encryption", "communication_partners", "essid", "positions",
                    "rates"]
        return []


if __name__ == '__main__':
    Database({"user": "postgres", "database": "pwnpi", "password": "postgres", "host": "localhost"})
