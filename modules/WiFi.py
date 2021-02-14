from scapy.layers.dot11 import *
from scapy.layers.eap import EAPOL
from scapy.all import conf
from time import sleep
from podb import DB

from pwnpy import Module

conf.verb = 0


class DeviceTypes(object):
    TYPE_STA = "sta"
    TYPE_AP = "ap"


class WiFiDevice(object):
    address = None
    essid = None
    rates = None
    device_type = None
    channel = -1
    encryption = None
    communication_partner = None

    def __init__(self, address):
        self.address = address

    @staticmethod
    def from_pkt(pkt):
        if pkt.haslayer(Dot11Beacon):
            s = WiFiAPDevice(pkt.getlayer(Dot11).addr2, pkt)
            r = WiFiSTADevice(pkt.getlayer(Dot11).addr1, pkt)
        elif pkt.haslayer(Dot11) and pkt.getlayer(Dot11).type == 2 and not pkt.haslayer(EAPOL):
            s = WiFiSTADevice(pkt.getlayer(Dot11).addr2, pkt)
            r = WiFiAPDevice(pkt.getlayer(Dot11).addr1, pkt)
        elif pkt.haslayer(Dot11ProbeReq) or pkt.haslayer(Dot11AssoReq) or pkt.haslayer(Dot11ReassoReq):
            s = WiFiSTADevice(pkt.getlayer(Dot11).addr2, pkt)
            r = WiFiAPDevice(pkt.getlayer(Dot11).addr1, pkt)
        elif pkt.haslayer(Dot11ProbeResp) or pkt.haslayer(Dot11AssoResp) or pkt.haslayer(Dot11ReassoResp):
            s = WiFiAPDevice(pkt.getlayer(Dot11).addr2, pkt)
            r = WiFiSTADevice(pkt.getlayer(Dot11).addr1, pkt)
        else:
            '''
            ds = pkt.FCfield & 0x3
            to_ds = ds & 0x1 != 0
            from_ds = ds & 0x2 != 0
            '''
            return None

        s.communication_partner = r.address
        r.communication_partner = s.address
        return s, r

    def parse_extra_data(self, pkt):
        # https://github.com/secdev/scapy/commit/32f081e08f5c3ee7a98606ed1a081bf4ee98fced is just for dot11beacon
        pass


class WiFiAPDevice(WiFiDevice):
    device_type = DeviceTypes.TYPE_AP

    def __init__(self, address, pkt):
        WiFiDevice.__init__(self, address)
        self.parse_extra_data(pkt)

    def parse_extra_data(self, pkt):
        if pkt.haslayer(Dot11Beacon):
            ns = pkt[Dot11Beacon].network_stats()
            self.essid = ns["ssid"]
            self.channel = ns["channel"]
            self.rates = ','.join(map(str, ns["rates"]))
            self.encryption = ','.join(ns["crypto"])


class WiFiSTADevice(WiFiDevice):
    device_type = DeviceTypes.TYPE_STA

    def __init__(self, address, pkt):
        WiFiDevice.__init__(self, address)
        self.parse_extra_data(pkt)

    def parse_extra_data(self, pkt):
        pass


BROADCAST = "ff:ff:ff:ff:ff:ff"


class WiFi(Module):
    def __init__(self, db: DB, **kwargs):
        Module.__init__(self, "WiFi", db)
        self.device = kwargs.get("device") or "wlan0"

    def _callback(self, pkt):
        if pkt.haslayer(Dot11):
            s, r = WiFiDevice.from_pkt(pkt)
            self.save_multiple([s, r])

    def on_start(self):
        sniff(self.device, prn=self._callback, filter="proto wlan")

    def work(self):
        sleep(0.1)
