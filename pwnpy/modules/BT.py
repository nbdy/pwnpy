import sys
from os.path import realpath
from subprocess import check_output
from time import sleep

from btpy import LEDevice, ClassicDevice, Beacon
from loguru import logger as log

from pwnpy import Module, is_root, Manager
from pwnpy.libs import ModuleType


class BT(Module):
    type = ModuleType.BT

    device = "hci0"

    seen_beacons = []
    seen_classic = []
    seen_le = []

    @staticmethod
    def is_le_scan_enabled():
        py_exe = realpath(sys.executable)
        return is_root() or b"cap_net_admin,cap_net_raw+eip" in check_output("getcap {}".format(py_exe), shell=True)

    def __init__(self, mgr: Manager, **kwargs):
        Module.__init__(self, "BT", mgr)
        if "device" in kwargs.keys():
            self.device = kwargs["device"]
        self.devs_types = [ClassicDevice, Beacon]
        self.shared_data["data"] = {
            "c": 0,
            "l": 0,
            "b": 0
        }
        if self.is_le_scan_enabled():
            log.debug("Either we are root or the python executable has appropriate capabilities")
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

    def update_beacon(self, devices):
        for dev in devices:
            if dev.address not in self.seen_beacons:
                self.seen_beacons.append(dev.address)
                self.shared_data["data"]["b"] += 1

    def update_shared_data(self, devices, dt):
        if dt == ClassicDevice:
            self.update_classic(devices)
        elif dt == LEDevice:
            self.update_le(devices)
        elif dt == Beacon:
            self.update_beacon(devices)

    def save_devices(self, devices):
        pos = self.mgr.get_shared_data_id("GPS")
        for dev in devices:
            if isinstance(dev, Beacon):
                del dev.packet
                dev.extra_info["encrypted_metadata"] = str(dev.extra_info["encrypted_metadata"])
            dd = dev.__dict__
            if pos:
                dd.update({"coordinates": pos})
            log.debug("Saving device: {}", dd)
            self.save(dd)

    def work(self):
        for dt in self.devs_types:
            devices = dt.scan()
            self.update_shared_data(devices, dt)
            self.save_devices(devices)
        sleep(0.2)
