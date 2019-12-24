from dataset import connect


class Database(object):
    db = None

    def __init__(self, cfg):
        self.db = connect(cfg["schema"])

    def insert(self, table, data):
        self.db[table].insert(data)
