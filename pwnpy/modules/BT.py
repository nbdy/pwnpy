from pwnpy import Module, is_root
from podb import DB
from btpy import LEDevice, ClassicDevice
from loguru import logger as log
from time import sleep


class BT(Module):
    def __init__(self, db: DB, **kwargs):
        Module.__init__(self, "BT", db)
        self.device = kwargs.get("device") or "hci0"
        self.devs_types = [ClassicDevice]
        if is_root():
            log.warning("Disabling BT LE scanning because we do not have root rights.")
            self.devs_types.append(LEDevice)

    def work(self):
        for dt in self.devs_types:
            devices = dt.scan()
            for device in devices:
                if "GPS" in self.mgr.shared_data:
                    device.__dict__.update(self.mgr.shared_data["GPS"])
        sleep(0.2)
