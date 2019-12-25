from os import system, path, mkdir, listdir
import netifaces
from scapy.config import conf
from scapy.layers.dot11 import *
from scapy.layers.eap import EAPOL
from subprocess import Popen, PIPE
from time import sleep

from libs import IThread


conf.verb = 0

# https://www.oreilly.com/library/view/80211-wireless-networks/0596100523/ch04.html


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


class WiFi(IThread):
    packets = []

    def __wifi_callback(self, pkt):
        if pkt.haslayer(Dot11):
            self.packets.append(pkt)
            data = WiFiDevice.from_pkt(pkt)
            if data is not None:
                if data[0].address.lower() != BROADCAST:
                    self.db.wifi_device_insert(data[0])
                if data[1].address.lower() != BROADCAST:
                    self.db.wifi_device_insert(data[1])

    @staticmethod
    def _find_wifi_interface():
        for i in netifaces.interfaces():
            if i.startswith('wl'):
                return i
        return None

    def _on_run(self):
        if not self.cfg["enable"]:
            self.do_run = False
        if self.cfg["autoInterface"]:
            self.cfg["interface"] = self._find_wifi_interface()
        if self.cfg["interface"] is None:
            self.stop_fatal("no interface")
            return
        if self.cfg["interface"] not in netifaces.interfaces():
            self.stop_fatal("no such interface: '%s'" % self.cfg["interface"])
            return
        if self.cfg["promiscuous"]:
            if not self.cfg["interface"].endswith("mon"):
                system("airmon-ng start %s" % self.cfg["interface"])  # todo monstart helper for rpi and other devices
                self.cfg["interface"] = "wlan0mon"
                system("ifconfig %s up" % self.cfg["interface"])
        if self.cfg["channels"] is None:
            self.cfg["channels"] = range(1, 14)
        self.log_info("sniffing on channels [%s]" % ','.join(str(x) for x in self.cfg["channels"]))
        if not path.isdir(self.cfg["hcx_output"]):
            if not self.cfg["hcx_output"].endswith("/"):
                self.cfg["hcx_output"] = self.cfg["hcx_output"]
            mkdir(self.cfg["hcx_output"])
            self.log_debug("created '%s'" % self.cfg["hcx_output"])
        if self.cfg["hcx_enable"]:
            self.log_debug("capturing handshakes to '%s'" % self.cfg["hcx_output"])

    def hcxdumptool(self):
        of = self.cfg["hcx_output"] + str(len(listdir(self.cfg["hcx_output"]))) + ".pcapng"
        cmd = ["hcxdumptool", "-i", self.cfg["interface"], "-o", of]
        print(cmd)
        p = Popen(cmd, stdout=PIPE, stderr=PIPE)
        sleep(self.cfg["hcx_time"])
        p.kill()

    def _work(self):
        for c in self.cfg["channels"]:
            self.log_debug("sniffing on channel %i" % c)
            system("iwconfig " + self.cfg["interface"] + " channel " + str(c))
            sniff(iface=self.cfg["interface"], prn=self.__wifi_callback, count=self.cfg["packetsPerChannel"],
                  timeout=self.cfg["timeoutPerChannel"], store=False, filter="type mgt")
            if self.cfg["hcx_enable"]:
                self.hcxdumptool()

    def stop(self):
        system("airmon-ng stop %s" % self.cfg["interface"])
