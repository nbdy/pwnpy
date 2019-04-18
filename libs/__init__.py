from threading import Thread


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


class IThread(T):
    name = "scanner"
    db = None
    cfg = None

    def __init__(self, db, cfg):
        T.__init__(self)
        self.db = db
        self.cfg = cfg
        self.do_run = self.cfg["enable"]
