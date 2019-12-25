from dataset import connect


class Database(object):
    db = None

    def __init__(self, cfg):
        self.db = connect(cfg["schema"])

    def insert(self, table, data):
        self.db[table.lower()].insert(data)

    def count(self, table):
        return len(self.db[table])

    def get(self, table, key, value):
        for i in self.db[table]:
            if i[key] == value:
                return i
        return None

    def current_position(self):
        tbl = self.db["gps"].table
        stmt = tbl.select(tbl.c.time)  # todo
