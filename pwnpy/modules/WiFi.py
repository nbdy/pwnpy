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

    shared_data = {
        "opn": 0,
        "wep": 0,
        "wpa": 0,
    }

    seen_ssids = []

    def __init__(self, mgr: Manager, **kwargs):
        Module.__init__(self, "WiFi", mgr)
        self.device = mgr.cfg["w-device"]

    @staticmethod
    def set_or_not(o: dict, n: dict, k: str):
        if k in n.keys():
            if k == "crypto":
                o[k] = ','.join(n[k])
            else:
                o[k] = n[k]
        return o

    def update_shared_data(self, i):
        if "ssid" in i.keys() and "crypto" in i.keys():
            s = i["ssid"]
            e = i["crypto"].lower()
            if s not in self.seen_ssids:
                self.seen_ssids.append(s)
                log.debug("Encryption: {0}", e)
                if "open" in e or "opn" in e:
                    self.shared_data["opn"] += 1
                elif "wep" in e:
                    self.shared_data["wep"] += 1
                elif "wpa" in e:
                    self.shared_data["wpa"] += 1

    def dot11_beacon_check(self, i, pkt):
        if Dot11Beacon in pkt:
            ns = pkt[Dot11Beacon].network_stats()
            i = self.set_or_not(i, ns, "ssid")
            i = self.set_or_not(i, ns, "rates")
            i = self.set_or_not(i, ns, "channel")
            i = self.set_or_not(i, ns, "country")
            i = self.set_or_not(i, ns, "crypto")
        return i

    def add_coordinate(self, i):
        if "GPS" in self.mgr.shared_data.keys() and self.mgr.shared_data["GPS"]["id"] is not None:
            i["coordinates"] = self.mgr.shared_data["GPS"]["id"]
        return i

    def process_dot11(self, pkt):
        i = {
            "addr1": pkt[Dot11].addr1,
            "addr2": pkt[Dot11].addr2,
            "addr3": pkt[Dot11].addr3,
            "addr4": pkt[Dot11].addr4,
            "rssi": pkt[RadioTap].dBm_AntSignal
        }
        i = self.add_coordinate(i)
        i = self.dot11_beacon_check(i, pkt)
        self.update_shared_data(i)
        self.save(i)

    def _callback(self, pkt):
        if Dot11 in pkt:
            self.process_dot11(pkt)

    def on_start(self):
        if geteuid() == 0:
            log.info("Enabling monitor mode on {0}.", self.device)
            system("sudo ifconfig {0} down; sudo iwconfig {0} mode monitor; sudo ifconfig {0} up".format(self.device))
        log.info("Going to sniff on {0} now.", self.device)
        sniff(iface=self.device, prn=self._callback)

    def work(self):
        sleep(0.1)
