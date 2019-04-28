from os import system, path, mkdir
import netifaces
from scapy.all import *
import binascii

from libs import IThread

# https://www.oreilly.com/library/view/80211-wireless-networks/0596100523/ch04.html


# https://github.com/Esser420/HalfWPAid/blob/master/halfwpaid.py
class HalfWPAHandshake(object):
    def __init__(self, 	ssid=None, ap_mac=None, client_mac=None,
                 aNonce=None, sNonce=None, mic=None, data=None):
        self.ascii_ap_mac = ap_mac
        self.ascii_client_mac = client_mac

        try:
            self.ap_mac = binascii.a2b_hex(ap_mac)
            self.client_mac = binascii.a2b_hex(client_mac)
        except Exception:
            self.ap_mac = None
            self.client_mac = None

        self.ssid = ssid
        self.aNonce = aNonce
        self.sNonce = sNonce
        self.mic = mic
        self.data = data

    def complete_info(self, half_handshake):
        if self.ap_mac is None and half_handshake.ap_mac is not None:
            self.ap_mac = half_handshake.ap_mac

        if self.client_mac is None and half_handshake.client_mac is not None:
            self.client_mac = half_handshake.client_mac

        if self.aNonce is None and half_handshake.aNonce is not None:
            self.aNonce = half_handshake.aNonce

        if self.sNonce is None and half_handshake.sNonce is not None:
            self.sNonce = half_handshake.sNonce

        if self.mic is None and half_handshake.mic is not None:
            self.mic = half_handshake.mic

        if self.data is None and half_handshake.data is not None:
            self.data = half_handshake.data

    def extract_info(self, packet):
        if EAPOL not in packet:
            return

        eapol_packet = packet["EAPOL"]
        # check if it is the first or second frame
        if eapol_packet.flags not in [17, 33]:
            return

        frame_number = 1 if eapol_packet.flags == 17 else 2

        if frame_number == 1:
            self.ascii_ap_mac = packet.src
            self.ascii_client_mac = packet.dst
            self.ap_mac = binascii.a2b_hex(packet.src.replace(":",""))
            self.client_mac = binascii.a2b_hex(packet.dst.replace(":",""))
            self.aNonce = eapol_packet.nonce
        else:
            self.ascii_ap_mac = packet.dst
            self.ascii_client_mac = packet.src
            self.ap_mac = binascii.a2b_hex(packet.dst.replace(":",""))
            self.client_mac = binascii.a2b_hex(packet.src.replace(":",""))
            self.sNonce = eapol_packet.nonce
            self.mic = eapol_packet.mic
            self.data = self._calculate_data_bytes(packet)

    @staticmethod
    def _calculate_data_bytes(pkt):
        if EAPOL not in pkt:
            return

        eapol_packet = pkt["EAPOL"]
        if eapol_packet.flags != 33:
            return

        eapol_offset = len(str(pkt)) - len(str(eapol_packet))
        mic_index = str(packet).index(eapol_packet.mic)
        data = str(pkt)[eapol_offset:mic_index] + "\x00" * 16 + str(packet)[mic_index+16:]

        return data

    def is_complete(self):
        return (self.ap_mac and self.client_mac and
                self.aNonce and self.sNonce and
                self.mic and self.data) is not None


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
        elif pkt.haslayer(Dot11) and pkt.getlayer(Dot11).type == 2L and not pkt.haslayer(EAPOL):
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


class WiFi(IThread):
    name = "wifi"
    packets = []

    def __wifi_callback(self, pkt):
        self.packets.append(pkt)
        # todo deauth
        if self.cfg["deauth"]:
            pass
        if pkt.haslayer(Dot11):
            data = WiFiDevice.from_pkt(pkt)
            if data is not None:
                if data[0].address != ETHER_BROADCAST.lower():
                    self.db.wifi_device_insert(data[0])
                if data[1].address != ETHER_BROADCAST.lower():
                    self.db.wifi_device_insert(data[1])

    def save_half_handshakes(self):
        half_handshakes = []
        for pkt in self.packets:
            if Dot11Beacon not in pkt or EAPOL not in pkt:
                continue
            ap = WiFiAPDevice(pkt.getlayer(Dot11).addr2, pkt)

            half_handshake = HalfWPAHandshake(ssid=ap.essid)
            half_handshake.extract_info(pkt)

            found_pair = False
            for hhandshake in half_handshakes:
                if hhandshake.ap_mac == half_handshake.ap_mac and \
                        hhandshake.client_mac == half_handshake.client_mac:
                    hhandshake.complete_info(half_handshake)
                    found_pair = True

            if not found_pair:
                half_handshakes.append(half_handshake)

        self.packets = []

        for hh in half_handshakes:
            if hh.is_complete():
                pass  # todo save

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
            print "[wifi] using interface:", self.cfg["interface"]
        if self.cfg["interface"] is None:
            self.do_run = False
            print "[wifi] dont have an interface"
            return
        if self.cfg["interface"] not in netifaces.interfaces():
            print "[wifi] interface '%s' does not exist" % self.cfg["interface"]
            self.do_run = False
        if self.cfg["promiscuous"]:
            if not self.cfg["interface"].endswith("mon"):
                system("airmon-ng start %s" % self.cfg["interface"])
                self.cfg["interface"] = "wlan0mon"
                system("ifconfig %s up" % self.cfg["interface"])
        if self.cfg["deauth"]:
            print "[wifi] deauthentication of stations is enabled"
            if not path.isdir(self.cfg["capturedHandshakesPath"]):
                mkdir(self.cfg["capturedHandshakesPath"])
                print "[wifi] created %s" % self.cfg["capturedHandshakesPath"]
            print "[wifi] capturing handshakes to %s" % self.cfg["capturedHandshakesPath"]

    def _work(self):
        for c in range(1, 14):
            system("iwconfig " + self.cfg["interface"] + " channel " + str(c))
            sniff(iface=self.cfg["interface"], prn=self.__wifi_callback, count=self.cfg["packetsPerChannel"],
                  timeout=self.cfg["timeoutPerChannel"], store=False)
            self.save_half_handshakes()

    def stop(self):
        system("airmon-ng stop %s" % self.cfg["interface"])
