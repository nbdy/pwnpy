import psycopg2
from json import dumps, loads

DATETIME_FORMAT = "'%Y-%m-%dT%H:%M:%S.%f'"


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
    def _build_array(items, delimiter=','):
        r = "{"
        for item in items:
            r += item + delimiter
        r = r[0:-1]
        r += '}'
        r = r.replace("'", "")
        return r

    def _check_table_valid(self, table):
        return table in self.get_table_names()

    query_position_insert = """INSERT INTO positions (longitude, latitude, altitude, speed, time) VALUES 
    ('%s', '%s', '%s', '%s', %s);"""

    def update_position(self, position):
        self._execute(self.query_position_insert % (position.longitude, position.latitude, position.altitude,
                                                    position.speed, position.time.strftime(DATETIME_FORMAT)), True)

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
                          device.address, device.communication_partner), fetchall=True)[0][0]
        if r != 0L:
            tmp = "UPDATE wifi SET positions = array_append(positions, '%s') WHERE address='%s'" % (
                self.get_newest_position_timestamp(), device.address)
        else:
            tmp = self.query_wifi_device_update % (self.get_newest_position_timestamp(), device.communication_partner,
                                                   device.address)
        self._execute(tmp, True)

    query_wifi_device_exists = """SELECT EXISTS(SELECT 1 FROM wifi WHERE address = '%s');"""

    def wifi_device_exists(self, address):
        return self._execute(self.query_wifi_device_exists % address, fetchall=True)[0][0]

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

    def _search_bluetooth_classic(self, r, query):
        i = 0
        while i < len(r["rows"]):
            positions = []
            for p in r["rows"][i][-1]:
                if len(positions) >= int(query["maxPositions"]):
                    break
                pos = self.get_position(p)
                positions.append({
                    "longitude": pos[0],
                    "latitude": pos[1],
                    "altitude": pos[2],
                    "speed": pos[3],
                    "timestamp": pos[4].strftime(DATETIME_FORMAT)
                })
            row = {
                "address": r["rows"][i][0],
                "name": r["rows"][i][1],
                "positions": positions
            }
            r["rows"][i] = row
            i += 1
        return r

    def _search_wifi(self, r, query):
        positions = []
        i = 0
        while i < len(r["rows"]):
            for p in r["rows"][i][-2]:
                if len(positions) >= int(query["maxPositions"]):
                    break
                pos = self.get_position(p)
                positions.append({
                    "longitude": pos[0],
                    "latitude": pos[1],
                    "altitude": pos[2],
                    "speed": pos[3],
                    "timestamp": pos[4].strftime(DATETIME_FORMAT)
                })
            print r["rows"][i]
            row = {
                "address": r["rows"][i][0],
                "device_type": r["rows"][i][1],
                "channel": r["rows"][2],
                "encryption": r["rows"][3],
                "communication_partners": r["rows"][4],
                "essid": r["rows"][5],
                "positions": positions,
                "rates": r["rows"][7]
            }
            r["rows"][i] = row
            i += 1
        return r

    def _search_bluetooth_le(self, r, query):
        positions = []
        i = 0
        while i < len(r["rows"]):
            for p in r["rows"][i][2]:
                if len(positions) >= int(query["maxPositions"]):
                    break
                pos = self.get_position(p)
                positions.append({
                    "longitude": pos[0],
                    "latitude": pos[1],
                    "altitude": pos[2],
                    "speed": pos[3],
                    "timestamp": pos[4].strftime(DATETIME_FORMAT)
                })
            print r["rows"][i]
            row = {
                "address": r["rows"][i][0],
                "name": r["rows"][i][1],
                "positions": positions,
                "rssi": r["rows"][i][3],
                "connectable": r["rows"][i][4],
                "advertisements": len(r["rows"][i][5])
            }
            r["rows"][i] = row
            i += 1
        return r

    def search(self, query):
        cn = self.get_column_names(query["table"])
        r = {
            "columns": cn,
            "rows": []
        }
        qry = "SELECT * FROM " + query["table"]
        if "filters" in query.keys():
            for f in query["filters"]:
                qry += f["column"] + "='" + f["value"] + "'"
        print qry
        r["rows"] = self._execute(qry, fetchall=True)
        if query["table"] == "bluetooth_classic":
            r = self._search_bluetooth_classic(r, query)
        elif query["table"] == "wifi":
            r = self._search_wifi(r, query)
        elif query["table"] == "bluetooth_le":
            r = self._search_bluetooth_le(r, query)
        print r["rows"]
        return r

    query_get_position = """SELECT * FROM positions WHERE time='%s';"""

    def get_newest_position(self):
        return self._execute(self.query_get_position % self.get_newest_position_timestamp(), fetchone=True)

    def get_position(self, timestamp):
        return self._execute(self.query_get_position % timestamp, fetchone=True)

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

    @staticmethod
    def get_table_names():
        return ["bluetooth_classic", "bluetooth_le", "manager", "positions", "wifi"]

    query_update_positions = """UPDATE %s SET positions = '%s' WHERE address = '%s';"""

    def _update_timestamps(self):
        table_names = ["bluetooth_classic", "bluetooth_le"]
        for table_name in table_names:
            qry = self.query_get_all % table_name
            for i in self._execute(qry, fetchall=True):
                addr = i[0]
                positions = i[2]
                new_positions = []
                for position in positions:
                    new_positions.append(position.strftime(DATETIME_FORMAT))
                self._execute(self.query_update_positions % (table_name, self._build_array(new_positions),
                                                             addr), True)

    query_update_start = """UPDATE manager SET start = '%s' WHERE id = '%s';"""
    query_update_end = """UPDATE manager SET end = '%s' WHERE id = '%s';"""

    def _update_manager_timestamps(self):
        rows = self._execute(self.query_get_all % "manager", fetchall=True)
        for r in rows:
            self._execute(self.query_update_start % (r[1].strftime(DATETIME_FORMAT), r[0]), True)
            self._execute(self.query_update_end % (r[2].strftime(DATETIME_FORMAT), r[0]), True)

    query_update_time = """UPDATE positions SET time = '%s' WHERE time = %s;"""

    def _update_position_time(self):
        rows = self._execute(self.query_get_all % "positions", fetchall=True)
        for r in rows:
            self._execute(self.query_update_time % (r[-1], r[-1].strftime(DATETIME_FORMAT)), True)

    query_update_wifi_positions = """UPDATE wifi SET positions='%s' WHERE address='%s';"""

    def _update_wifi_positions(self):
        rows = self._execute(self.query_get_all % "wifi", fetchall=True)
        for r in rows:
            positions = r[-2]
            new_positions = []
            for position in positions:
                new_positions.append(position.strftime(DATETIME_FORMAT))
            self._execute(self.query_update_wifi_positions % (self._build_array(new_positions), r[0]), True)

    def timestamp_migration(self):
        print "[database] migrating bluetooth timestamps"
        self._update_timestamps()
        print "[database] migrating manger start stop timestamps"
        self._update_manager_timestamps()
        print "[database] migrating positions timestamps"
        self._update_position_time()
        print "[database] migrating wifi timestamps"
        self._update_wifi_positions()


if __name__ == '__main__':
    Database({"user": "postgres", "database": "pwnpi", "password": "postgres", "host": "localhost"})
