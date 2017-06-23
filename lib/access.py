from scapy.all import *

ssids = {}
print("BSSID\t\t\tESSID\t\tEncryption\n")
hiddenNets = []

def dot11pkt(pkt):
    if Dot11Beacon not in pkt and Dot11ProbeResp not in pkt:
        return
    bssid = pkt[Dot11].addr3
    if bssid in ssids:
        return
    pinfo = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}""{Dot11ProbeResp:%Dot11ProbeResp.cap%}").split('+')
    ssid = ''
    encryption = ''
    dpkt = pkt[Dot11Elt]
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
        if str(addr2) not in hiddenNets:
            print(str(addr2) + "\tHidden\t\t" + str(encryption))
            hiddenNets.append(addr2)
    else:
        print(str(bssid) + "\t" + str(ssid.decode()) + "\t" + str(encryption))
    ssids[bssid] = encryption

sniff(iface="wlan0mon", prn=dot11pkt)
