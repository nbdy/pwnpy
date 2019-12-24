from . import IThread


class Module(IThread):
    def __init__(self, db, cfg):
        IThread.__init__(self, db, cfg)

    def save(self, data):
        self.db.insert(self.name, data)
