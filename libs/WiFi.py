from time import sleep

from scapy.all import sniff
from scapy.layers.dot11 import Dot11

from libs import Scanner


class DeviceTypes(object):
    TYPE_STA = 0
    TYPE_AP = 1
    DUMMY = -1


class EncryptionTypes(object):
    TYPE_NONE = 0
    TYPE_WEP = 1
    TYPE_WPA = 2
    TYPE_WPA2 = 3
    TYPE_RADIUS = 4


class StaticFunctions(object):
    @staticmethod
    def sta_or_ap(pkt):
        if pkt.haslayer(Dot11):
            '''
            if pkt.type == 0 and pkt.subtype in [1, 3, 5, 8]:
                return DeviceTypes.TYPE_AP
            elif pkt.type == 0 and pkt.subtype in [0, 2, 4, 10, 11, 12]:
                return DeviceTypes.TYPE_STA
            '''

        if pkt.haslayer(Dot11) and pkt.type == 2:
            ds = pkt.FCfield & 0x3
            tds = ds & 0x01 != 0
            fds = ds & 0x2 != 0
            if tds and not fds:
                return DeviceTypes.TYPE_AP
            if not tds and fds:
                return DeviceTypes.TYPE_STA
        return None

    @staticmethod
    def essid(pkt):
        return ""  # todo

    @staticmethod
    def encryption(pkt):
        return EncryptionTypes.TYPE_NONE  # todo


class WiFiDevice(object):
    address = None
    device_type = None
    channel = None
    encryption = None
    communication_partners = None

    def __init__(self, address, **kwargs):
        self.address = address
        if "device_type" in kwargs:
            self.device_type = kwargs.get("device_type")
        if "channel" in kwargs:
            self.channel = kwargs.get("channel")
        if "encryption" in kwargs:
            self.encryption = kwargs.get("encryption")
        if "communication_partners" in kwargs:
            self.communication_partners = kwargs.get("communication_partners")
        else:
            self.communication_partners = []

    @staticmethod
    def dummy():
        return WiFiDevice("FF:FF:FF:FF:FF:FF", device_type=DeviceTypes.DUMMY, channel=-1,
                          encryption=EncryptionTypes.TYPE_NONE)

    @staticmethod
    def from_pkt(pkt):
        sa = StaticFunctions.sta_or_ap(pkt)
        if sa == DeviceTypes.TYPE_AP:
            s = WiFiAPDevice(pkt.addr2)
            r = WiFiSTADevice(pkt.addr3)
        elif sa == DeviceTypes.TYPE_STA:
            s = WiFiSTADevice(pkt.addr2)
            r = WiFiAPDevice(pkt.addr3)
        else:
            return None

        s.communication_partners.append(r.address)
        r.communication_partners.append(s.address)
        # todo record target

        for v in [s, r]:
            if isinstance(v, WiFiAPDevice):
                v.essid = StaticFunctions.essid(pkt)
            elif isinstance(v, WiFiSTADevice):
                pass  # todo

        return [s, r]


class WiFiAPDevice(WiFiDevice):
    essid = None
    device_type = DeviceTypes.TYPE_AP

    def __init__(self, address, **kwargs):
        WiFiDevice.__init__(self, address)
        self.device_type = DeviceTypes.TYPE_AP
        if "essid" in kwargs:
            self.essid = kwargs.get("essid")
        else:
            self.essid = ""
        if "connected_devices" in kwargs:
            self.connected_devices = kwargs.get("connected_devices")
        else:
            self.connected_devices = []
        if "channel" in kwargs:
            self.channel = kwargs.get("channel")
        else:
            self.channel = -1
        if "encryption" in kwargs:
            self.encryption = kwargs.get("encryption")
        else:
            self.encryption = EncryptionTypes.TYPE_NONE

    @staticmethod
    def dummy():
        return WiFiAPDevice("FF:FF:FF:FF:FF:FF")


class WiFiSTADevice(WiFiDevice):
    device_type = DeviceTypes.TYPE_STA

    def __init__(self, address, **kwargs):
        WiFiDevice.__init__(self, address)
        self.device_type = DeviceTypes.TYPE_STA


class WiFi(Scanner):
    name = "wifi"

    def __wifi_callback(self, pkt):
        devs = WiFiDevice.from_pkt(pkt)
        if devs is None:
            return
        for dev in devs:
            if dev is not None:
                self.db.update_wifi_device(dev)

    def _on_run(self):
        if not self.cfg["enable"]:
            self.do_run = False
        if self.cfg["interface"] is None:
            self.do_run = False
        if self.do_run:
            sniff(iface=self.cfg["interface"], prn=self.__wifi_callback)

    def _work(self):
        sleep(self.cfg.sleep_time)

    def stop(self):
        if self.cfg["interface"]:
            print self.cfg["interface"][-5:-2]
