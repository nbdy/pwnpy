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

    def build_database(self):
        cr = self.cn.cursor()
        cr.execute("CREATE TABLE IF NOT EXISTS positions ("
                   "longitude float NOT NULL,"
                   "latitude float NOT NULL,"
                   "altitude float NOT NULL,"
                   "speed float NOT NULL,"
                   "time timestamp NOT NULL"
                   ");")
        self.cn.commit()
        cr.execute("CREATE TABLE IF NOT EXISTS wifi ("
                   "address macaddr PRIMARY KEY NOT NULL,"
                   "device_type text NOT NULL,"
                   "channel int NOT NULL,"
                   "encryption text NOT NULL,"
                   "communication_partners text[],"
                   "essid text,"
                   "position timestamp NOT NULL"
                   ");")
        self.cn.commit()
        cr.execute("CREATE TABLE IF NOT EXISTS bluetooth_classic ("
                   "address macaddr PRIMARY KEY NOT NULL,"
                   "name text,"
                   "positions timestamp[]"
                   ");")
        self.cn.commit()
        cr.execute("CREATE TABLE IF NOT EXISTS bluetooth_le ("
                   "address macaddr PRIMARY KEY NOT NULL,"
                   "name text,"
                   "positions timestamp[],"
                   "rssi integer,"
                   "connectable boolean,"
                   "advertisements text[][]"
                   ");")
        cr.close()

    def __init__(self, cfg):
        self.cfg = cfg
        self.cn = psycopg2.connect(self._build_connection_string())
        self.build_database()

    query_position_insert = """INSERT INTO positions (longitude, latitude, altitude, speed, time) VALUES 
    ('%s', '%s', '%s', '%s', '%s');"""

    def update_position(self, position):
        cr = self.cn.cursor()
        tmp = self.query_position_insert % (
            position.longitude, position.latitude, position.altitude, position.speed, position.time)
        cr.execute(tmp)
        self.cn.commit()
        cr.close()

    query_position_get_newest = """SELECT * FROM positions ORDER BY time DESC LIMIT 1;"""

    def get_newest_position_timestamp(self):
        cr = self.cn.cursor()
        cr.execute(self.query_position_get_newest)
        tmp = cr.fetchall()
        cr.close()
        return tmp[-1][-1]

    def update_wifi_device(self, device):
        cr = self.cn.cursor()
        tmp = """INSERT INTO wifi (device_type, channel, encryption, communication_partners, essid, 
    position) VALUES ('%s', '%s', '%s', '%s', '%s', '%s');""" % (device.device_type, device.channel,
                                                                 device.encryption, device.communication_partners,
                                                                 device.essid, self.get_newest_position_timestamp())
        cr.execute(tmp)
        self.cn.commit()
        cr.close()

    query_bluetooth_classic_device_exists = """SELECT EXISTS(SELECT 1 FROM bluetooth_classic WHERE address = '%s');"""

    def bluetooth_classic_device_exists(self, address):
        cr = self.cn.cursor()
        tmp = self.query_bluetooth_classic_device_exists % address
        cr.execute(tmp)
        r = cr.fetchall()
        cr.close()
        return r[0][0]

    query_bluetooth_classic_device_update = """UPDATE bluetooth_classic SET positions = array_append(positions, '%s') 
    WHERE address = '%s';"""

    def bluetooth_classic_device_update(self, device):
        cr = self.cn.cursor()
        tmp = self.query_bluetooth_classic_device_update % (self.get_newest_position_timestamp(), device.address)
        cr.execute(tmp)
        self.cn.commit()
        cr.close()

    query_bluetooth_classic_device_insert = """INSERT INTO bluetooth_classic (address, name, positions) 
    VALUES ('%s', '%s', '%s');"""

    def bluetooth_classic_device_insert(self, device):
        if self.bluetooth_classic_device_exists(device.address):
            self.bluetooth_classic_device_update(device)
        else:
            cr = self.cn.cursor()
            tmp = self.query_bluetooth_classic_device_insert % (device.address, device.name, device.device_type,
                                                                self.get_newest_position_timestamp())
            cr.execute(tmp)
            self.cn.commit()
            cr.close()

    query_bluetooth_le_device_exists = """SELECT EXISTS(SELECT 1 FROM bluetooth_le WHERE address = '%s');"""

    def bluetooth_le_device_exists(self, address):
        cr = self.cn.cursor()
        tmp = self.query_bluetooth_le_device_exists % address
        cr.execute(tmp)
        r = cr.fetchall()
        cr.close()
        return r[0][0]

    query_bluetooth_le_device_update = """UPDATE bluetooth_le SET positions = array_append(positions, '%s') 
    WHERE address = '%s';"""

    def bluetooth_le_device_update(self, device):
        cr = self.cn.cursor()
        tmp = self.query_bluetooth_le_device_update % (self.get_newest_position_timestamp(), device.address)
        cr.execute(tmp)
        self.cn.commit()
        cr.close()

    query_bluetooth_le_device_insert = """INSERT INTO bluetooth_le (address, name, positions, rssi, connectable, 
    advertisements) VALUES ('%s', '%s', '%s', '%s', '%s', '%s');"""

    def bluetooth_le_device_insert(self, device):
        if self.bluetooth_le_device_exists(device.address):
            self.bluetooth_le_device_update(device)
        else:
            cr = self.cn.cursor()
            tmp = self.query_bluetooth_le_device_insert % (device.address, device.name,
                                                           self.get_newest_position_timestamp(), device.rssi,
                                                           device.connectable, device.advertisements)
            cr.execute(tmp)
            self.cn.commit()
            cr.close()
