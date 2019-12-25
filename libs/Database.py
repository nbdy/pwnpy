from dataset import connect


class Database(object):
    db = None

    def __init__(self, cfg):
        self.db = connect(cfg["schema"])

    def insert(self, table, data):
        self.db[table.lower()].insert(data)

    def count(self, table):
        return len(self.db[table])

    def get(self, table, key):
        return self.db[table]