from pwnpy import Module, is_root, Manager
from pwnpy.libs import ModuleType
from btpy import LEDevice, ClassicDevice
from loguru import logger as log
from time import sleep


class BT(Module):
    type = ModuleType.BT

    seen_classic = []
    seen_le = []

    def __init__(self, mgr: Manager, **kwargs):
        Module.__init__(self, "BT", mgr)
        self.device = kwargs["device"] or "hci0"
        self.devs_types = [ClassicDevice]
        self.shared_data["data"] = {
            "c": 0,
            "l": 0
        }
        if is_root():
            self.devs_types.append(LEDevice)
        else:
            log.warning("Disabling BT LE scanning because we do not have root rights.")

    def update_classic(self, devices):
        for dev in devices:
            if dev.address not in self.seen_classic:
                self.seen_classic.append(dev.address)
                self.shared_data["data"]["c"] += 1

    def update_le(self, devices):
        for dev in devices:
            if dev.address not in self.seen_le:
                self.seen_le.append(dev.address)
                self.shared_data["data"]["l"] += 1

    def update_shared_data(self, devices, dt):
        if dt == ClassicDevice:
            self.update_classic(devices)
        elif dt == LEDevice:
            self.update_le(devices)

    def save_devices(self, devices):
        pos = self.mgr.get_shared_data_id("GPS")
        for dev in devices:
            dd = dev.__dict__
            if pos:
                dd = dd.update({"coordinates": pos})
            self.save(dd)

    def work(self):
        for dt in self.devs_types:
            devices = dt.scan()
            self.update_shared_data(devices, dt)
            self.save_devices(devices)
        sleep(0.2)
