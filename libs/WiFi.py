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
    device_type = None
    channel = -1
    encryption = EncryptionTypes.TYPE_NONE
    communication_partners = []

    def __init__(self, address):
        self.address = address

    @staticmethod
    def from_pkt(pkt):
        s = None
        r = None

        if pkt.haslayer(Dot11Beacon):
            s = WiFiAPDevice(pkt.getlayer(Dot11).addr2, pkt)
            r = WiFiSTADevice(pkt.getlayer(Dot11).addr1, pkt)
        elif pkt.haslayer(Dot11) and pkt.getlayer(Dot11).type == 2L and not pkt.haslayer(EAPOL):
            s = WiFiSTADevice(pkt.getlayer(Dot11).addr2, pkt)
            r = WiFiAPDevice(pkt.getlayer(Dot11).addr1, pkt)
        else:
            '''
            ds = pkt.FCfield & 0x3
            to_ds = ds & 0x1 != 0
            from_ds = ds & 0x2 != 0
            '''
            print pkt.__dict__
            return None

        s.communication_partners.append(r.address)
        r.communication_partners.append(s.address)
        return s, r

    def parse_extra_data(self, pkt):
        self.channel = int(ord(pkt[Dot11Elt:3].info))

        '''
        crypto = set()
        while isinstance(p, Dot11Elt):
            if p.ID == 0:
                ssid = p.info
            elif p.ID == 3:
                channel = ord(p.info)
            elif p.ID == 48:
                crypto.add("WPA2")
            elif p.ID == 221 and p.info.startswith('\x00P\xf2\x01\x01\x00'):
                crypto.add("WPA")
            p = p.payload
        if not crypto:
            if 'privacy' in cap:
                crypto.add("WEP")
            else:
                crypto.add("OPN")
        '''


class WiFiAPDevice(WiFiDevice):
    essid = None
    device_type = DeviceTypes.TYPE_AP

    def __init__(self, address, pkt):
        WiFiDevice.__init__(self, address)
        self.essid = pkt.info
        self.parse_extra_data(pkt)
        print self.__dict__


class WiFiSTADevice(WiFiDevice):
    device_type = DeviceTypes.TYPE_STA

    def __init__(self, address, pkt):
        WiFiDevice.__init__(self, address)
        self.parse_extra_data(pkt)
        print self.__dict__


class WiFi(Scanner):
    name = "wifi"

    def __wifi_callback(self, pkt):
        data = WiFiDevice.from_pkt(pkt)
        if data is not None:
            print data[0].address, ">", data[1].address
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
                system("ifconfig %s up" % self.cfg["interface"])
                self.cfg["interface"] = "wlan0mon"

    def _work(self):
        for c in range(1, 14):
            system("iwconfig " + self.cfg["interface"] + " channel " + str(c))
            sniff(iface=self.cfg["interface"], prn=self.__wifi_callback, count=self.cfg["packetsPerChannel"],
                  timeout=self.cfg["timeoutPerChannel"], store=False)

    def stop(self):
        system("airmon-ng stop %s" % self.cfg["interface"])
