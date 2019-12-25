from libs import IThread


class UI(IThread):
    def _on_run(self):
        self.stop_fatal("not implemented")

    def _work(self):
        pass
