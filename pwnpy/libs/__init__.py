from time import sleep

from runnable import Runnable
from podb import DB, DBEntry


class Module(Runnable):
    name: str = "DefaultModule"
    db: DB = None
    shared_data = {}

    def __init__(self, name: str, mgr):
        Runnable.__init__(self)
        self.name = name
        self.mgr = mgr

    @staticmethod
    def sleep(secs: float):
        sleep(secs)

    def save(self, data: DBEntry):
        self.mgr.db.upsert(data)

    def save_multiple(self, data: list[DBEntry]):
        self.mgr.db.upsert_many(data)
