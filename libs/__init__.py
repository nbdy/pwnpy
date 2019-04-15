from datetime import datetime
from threading import Thread
from uuid import uuid1


class Object(object):
    def _parse_kwargs(self, kwargs):
        kk = kwargs.keys()
        lk = self.__dict__.keys()
        for k in kk:
            if k in lk:
                self.__dict__[k] = kwargs.get(k)


class T(Thread):
    name = "default"
    daemon = True
    do_run = False

    def __init__(self):
        Thread.__init__(self)

    def _work(self):
        pass

    def _on_run(self):
        pass

    def _on_stop(self):
        pass

    def run(self):
        print "[" + self.name + "] running"
        self._on_run()
        while self.do_run:
            self._work()

    def stop(self):
        print "[" + self.name + "] stopping"
        self.do_run = False
        self._on_stop()


class DBObject(Object):
    uuid = None
    created = None
    last_modified = None

    def __init__(self, **kwargs):
        Object._parse_kwargs(self, kwargs)
        if "uuid" in kwargs:
            self.uuid = kwargs.get("uuid")
        else:
            self.uuid = uuid1()
        self.created = datetime.now()
        self.last_modified = self.created

    def save(self, db):
        db.update(self)

    @staticmethod
    def load(db, uuid):
        return db.get(uuid)

    @staticmethod
    def keys():
        return ["uuid", "created", "last_modified"]


class Device(DBObject):
    address = None
    positions = None  # just the ids

    def __init__(self, address, **kwargs):
        DBObject.__init__(self)
        self.address = address
        self.positions = []

    @staticmethod
    def keys():
        return DBObject.keys() + ["address", "positions"]

    @staticmethod
    def dummy():
        return Device("FF:FF:FF:FF:FF:FF")


class Scanner(T):
    name = "scanner"
    db = None
    cfg = None

    def __init__(self, db, cfg):
        T.__init__(self)
        self.db = db
        self.cfg = cfg
