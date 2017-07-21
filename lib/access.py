from colors import *
from scapy.all import *

ssids = {}
hiddenNets = []

def printtabs():
    print("{1}BSSID{0} \t\t\t {2}ESSID{0} \t\t {3}CHANNEL{0}\t{4}ENC{0}".format(RST, CY, RD, BLUE, GR))
    print("{}----------------------------------------------------------------{}".format(BL, RST))

def wlansniff(pkt):
        if Dot11Beacon not in pkt and Dot11ProbeResp not in pkt:
            return
        bssid = pkt[Dot11].addr3
        if bssid in ssids:
            return
        pinfo = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}""{Dot11ProbeResp:%Dot11ProbeResp.cap%}").split('+')
        ssid = ''
        encryption = ''
        dpkt = pkt[Dot11Elt]
        channel = int(ord(pkt[Dot11Elt:3].info))
        while dpkt:
            if dpkt.ID == 0:
                ssid = dpkt.info
            elif dpkt.ID == 48:
                encryption = "WPA"
            elif dpkt.ID == 221 and dpkt.info.startswith(b'\x00P\xf2\x01'):
                encryption = "WPA2"
            dpkt = dpkt.payload
        if not encryption:
            if "privacy" in pinfo:
                encryption = "WEP"
            else:
                encryption = "Open"
        if pkt[Dot11Elt].info.decode() == '':
            addr2 = pkt[Dot11].addr2
            if str(addr) not in hiddenNets:
                ssid = "Hidden"
                hiddenNets.append(addr2)
        print("{1}{2}{0}\t {3}{4}{0}\t  {5}{6}{0}\t\t{7}{8}{0}".format(RST, CY, bssid, RD, ssid.decode(), BLUE, channel, GR, encryption))
        ssids[bssid] = encryption
