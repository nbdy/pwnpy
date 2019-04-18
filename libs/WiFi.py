from time import sleep
from os import system

import netifaces
from scapy.all import *

from libs import Scanner

# https://www.oreilly.com/library/view/80211-wireless-networks/0596100523/ch04.html


class DeviceTypes(object):
    TYPE_STA = "sta"
    TYPE_AP = "ap"


class EncryptionTypes(object):
    TYPE_NONE = "none"
    TYPE_WEP = "wep"
    TYPE_WPA = "wpa"
    TYPE_WPA2 = "wpa2"
    TYPE_RADIUS = "radius"


class WiFiDevice(object):
    address = None
    essid = None
    rates = None
    device_type = None
    channel = -1
    encryption = EncryptionTypes.TYPE_NONE
    communication_partner = None

    def __init__(self, address):
        self.address = address

    @staticmethod
    def from_pkt(pkt):
        if pkt.haslayer(Dot11Beacon):
            s = WiFiAPDevice(pkt.getlayer(Dot11).addr2, pkt)
            r = WiFiSTADevice(pkt.getlayer(Dot11).addr1, pkt)
        elif pkt.haslayer(Dot11) and pkt.getlayer(Dot11).type == 2L and not pkt.haslayer(EAPOL):
            s = WiFiSTADevice(pkt.getlayer(Dot11).addr2, pkt)
            r = WiFiAPDevice(pkt.getlayer(Dot11).addr1, pkt)
        elif pkt.haslayer(Dot11ProbeReq):
            s = WiFiSTADevice(pkt.getlayer(Dot11).addr2, pkt)
            r = WiFiAPDevice(pkt.getlayer(Dot11).addr1, pkt)
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
        self.essid = pkt.info
        self.parse_extra_data(pkt)

    def parse_extra_data(self, pkt):
        crypto = ""
        p = pkt.payload
        while isinstance(p, Dot11Elt):
            if p.ID == 0:
                self.essid = p.info
            elif p.ID == 3:
                self.channel = ord(p.info)
            elif isinstance(p, Dot11EltRates):
                self.rates = p.rates
            elif isinstance(p, Dot11EltRSN):
                crypto += EncryptionTypes.TYPE_WPA2 + ","
            elif p.ID == 221:
                if isinstance(p, Dot11EltMicrosoftWPA) or \
                        p.info.startswith('\x00P\xf2\x01\x01\x00'):
                    crypto += EncryptionTypes.TYPE_WPA + ","
            p = p.payload
        if not crypto:
            try:
                if pkt.cap.privacy:
                    crypto += EncryptionTypes.TYPE_WEP + ","
                else:
                    crypto += EncryptionTypes.TYPE_NONE + ","
            except AttributeError:
                crypto += EncryptionTypes.TYPE_NONE + ","
        self.encryption = crypto[0:-2]


class WiFiSTADevice(WiFiDevice):
    device_type = DeviceTypes.TYPE_STA

    def __init__(self, address, pkt):
        WiFiDevice.__init__(self, address)
        self.parse_extra_data(pkt)

    def parse_extra_data(self, pkt):
        crypto = ""
        p = pkt.payload
        while isinstance(p, Dot11Elt):
            if p.ID == 3:
                self.channel = ord(p.info)
            elif isinstance(p, Dot11EltRates):
                self.rates = p.rates
            elif isinstance(p, Dot11EltRSN):
                crypto += EncryptionTypes.TYPE_WPA2 + ","
            elif p.ID == 221:
                if isinstance(p, Dot11EltMicrosoftWPA) or \
                        p.info.startswith('\x00P\xf2\x01\x01\x00'):
                    crypto += EncryptionTypes.TYPE_WPA + ","
            p = p.payload
        if not crypto:
            crypto += EncryptionTypes.TYPE_NONE + ","
        self.encryption = crypto[0:-2]


class WiFi(Scanner):
    name = "wifi"

    def __wifi_callback(self, pkt):
        data = WiFiDevice.from_pkt(pkt)
        if data is not None:
            if data[0].address != ETHER_BROADCAST:
                self.db.wifi_device_insert(data[0])
            if data[1].address != ETHER_BROADCAST:
                self.db.wifi_device_insert(data[1])

    def _on_run(self):
        if not self.cfg["enable"]:
            self.do_run = False
        if self.cfg["interface"] is None:
            self.do_run = False
        if self.cfg["interface"] not in netifaces.interfaces():
            print "[wifi] interface '%s' does not exist" % self.cfg["interface"]
            self.do_run = False
        if self.cfg["promiscuous"]:
            if not self.cfg["interface"].endswith("mon"):
                system("airmon-ng start %s" % self.cfg["interface"])
                self.cfg["interface"] = "wlan0mon"
                system("ifconfig %s up" % self.cfg["interface"])

    def _work(self):
        for c in range(1, 14):
            system("iwconfig " + self.cfg["interface"] + " channel " + str(c))
            sniff(iface=self.cfg["interface"], prn=self.__wifi_callback, count=self.cfg["packetsPerChannel"],
                  timeout=self.cfg["timeoutPerChannel"], store=False)

    def stop(self):
        system("airmon-ng stop %s" % self.cfg["interface"])
