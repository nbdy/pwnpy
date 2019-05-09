from threading import Thread


class T(Thread):
    daemon = True
    do_run = False

    def __init__(self):
        Thread.__init__(self)

    def _work(self):
        pass

    def _on_run(self):
        pass

    def _on_end(self):
        self._log("stopped")
        self.stop()

    def _on_stop(self):
        self.stop()

    def _log(self, msg):
        print("[" + self.__class__.__name__ + "] " + msg)

    def run(self):
        self._log("running")
        self._on_run()
        while self.do_run:
            self._work()
        self._on_end()

    def stop(self):
        self._log("stopping")
        self.do_run = False


class IThread(T):
    db = None
    cfg = None

    def __init__(self, db, cfg):
        T.__init__(self)
        self.db = db
        self.cfg = cfg
        self.do_run = self.cfg["enable"]
