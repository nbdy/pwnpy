from pwnpy import Module, is_root, Manager
from pwnpy.libs import ModuleType
from btpy import LEDevice, ClassicDevice
from podb import DBEntry
from loguru import logger as log
from time import sleep


class BT(Module):
    type = ModuleType.BT

    def __init__(self, mgr: Manager, **kwargs):
        Module.__init__(self, "BT", mgr)
        self.device = kwargs.get("device") or "hci0"
        self.devs_types = [ClassicDevice]
        if is_root():
            self.devs_types.append(LEDevice)
        else:
            log.warning("Disabling BT LE scanning because we do not have root rights.")

    def work(self):
        for dt in self.devs_types:
            devices = dt.scan()
            for device in devices:
                if "GPS" in self.mgr.shared_data:
                    device.__dict__.update(self.mgr.shared_data["GPS"])
                entry = DBEntry(**device.__dict__)
                log.debug("Found: {} | {}", device.name, device.address)
                self.save(entry)
        sleep(0.2)
