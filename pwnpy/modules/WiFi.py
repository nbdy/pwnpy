from scapy.layers.dot11 import *
from scapy.all import conf
from time import sleep
from os import geteuid, system
from pwnpy import Module, Manager
from pwnpy.libs import ModuleType, log

conf.verb = 0


BROADCAST = "ff:ff:ff:ff:ff:ff"


class WiFi(Module):
    type = ModuleType.WIFI

    def __init__(self, mgr: Manager, **kwargs):
        Module.__init__(self, "WiFi", mgr)
        self.device = mgr.cfg["w-device"]

    def _callback(self, pkt):
        if Dot11 in pkt:
            i = {
                "addr1": pkt[Dot11].addr1,
                "addr2": pkt[Dot11].addr2,
                "addr3": pkt[Dot11].addr3,
                "addr4": pkt[Dot11].addr4,
            }
            if Dot11Beacon in pkt:
                ns = pkt[Dot11Beacon].network_stats()
                i.update(ns)
            self.save(i)

    def on_start(self):
        if geteuid() == 0:
            log.info("Enabling monitor mode on {0}.", self.device)
            system("sudo airmon-ng start {0} && sudo ifconfig wlan0mon up".format(self.device))
            self.device = "wlan0mon"
        log.info("Going to sniff on {0} now.", self.device)
        sniff(iface=self.device, prn=self._callback)

    def work(self):
        sleep(0.1)
