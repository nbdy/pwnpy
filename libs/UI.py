
from . import IThread


class UI(IThread):
    def _on_run(self):
        pass

    def _work(self):
        pass

    def _on_end(self):
        self._log("ended")
