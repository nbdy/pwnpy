from dataset import connect


class Database(object):
    db = None

    def __init__(self, cfg):
        self.db = connect(cfg["schema"])

    def insert(self, table, data):
        self.db[table.lower()].insert(data)

    def count(self, table):
        return len(self.db[table])

    def counts(self):
        r = {}
        for t in self.db.tables:
            r[t] = len(self.db[t])
        return r

    def get(self, table, key, value):
        for i in self.db[table]:
            if i[key] == value:
                return i
        return None

    def get_columns(self, table):
        return self.db[table].columns

    def get_tables(self):
        return self.db.tables

    def current_position(self):
        tbl = self.db["gps"].table
        # stmt = tbl.select(tbl.c.time)  # todo
        return None
