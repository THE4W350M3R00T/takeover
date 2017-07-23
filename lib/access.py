from lib.colors import *
from scapy.all import *
import os, sys, time
import threading

ssids = {}
hiddenNets = []

class wireless:

    def __init__(self, iface):
        self.iface = iface
        self.active = True

    def printtabs(self):
        print("{1}BSSID{0} \t\t\t {2}ESSID{0} \t\t {3}CHANNEL{0}\t{4}ENC{0}".format(RST, CY, RD, BLUE, GR))
        print("{}----------------------------------------------------------------{}".format(BL, RST))
    
    def sniffer(self, pkt):
        if Dot11Beacon not in pkt and Dot11ProbeResp not in pkt:
            return
        bssid = pkt[Dot11].addr3
        if bssid in ssids:
            return
        pinfo = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}""{Dot11ProbeResp:%Dot11ProbeResp.cap%}")
        ssid = ''
        enc = ''
        channel = 0
        dpkt = pkt[Dot11Elt]
        while isinstance(dpkt, Dot11Elt):
            try:
                if dpkt.ID == 0:
                    ssid = dpkt.info
                if dpkt.ID == 3:
                    channel += ord(dpkt.info)
                elif dpkt.ID == 48:
                    enc = 'WPA2'
                elif dpkt.ID == 221 and dpkt.info.startswith(b'\x00P\xf2\x01\x01\x00'):
                    enc = 'WPA'
                dpkt = dpkt.payload
                if not enc:
                    if 'privacy' in pinfo:
                        enc = 'WEP'
                    else:
                        enc = 'OPEN'
                if pkt[Dot11Elt].info.decode() == '':
                    addr2 = pkt[Dot11].addr2
                    if str(addr) not in hiddenNets:
                        ssid = "Hidden"
                        hiddenNets.append(addr2)
            except KeyboardInterrupt:
                sys.exit(1)
        try:
            print("{1}{2}{0}\t {3}{4}{0}\t  {5}{6}{0}\t\t{7}{8}{0}".format(RST, CY, bssid, RD, ssid.decode(), BLUE, channel, GR, enc))
        except KeyboardInterrupt:
            sys.exit(1)
        except:
            print("{1}{2}{0}\t {3}{4}{0}\t\t  {5}{6}{0}\t\t{7}{8}{0}".format(RST, CY, bssid, RD, ssid, BLUE, channel, GR, enc))

        ssids[bssid] = enc
    
    def hopping(self):
        channel = 1
        try:
            while self.active:
                try:
                    if channel == 14:
                        channel = 1
                    else:
                        while channel != 14:
                            try:
                                os.system("iwconfig {} channel {}".format(self.iface, str(channel)))
                                channel += 1
                                time.sleep(0.1)
                            except KeyboardInterrupt:
                                print("hellO")
                                self.active = False
                                break
                except KeyboardInterrupt:
                    print("yo")
                    self.active = False
        except:
            pass

    def Main(self):
        self.printtabs()
        t = threading.Thread(target=self.hopping)
        t.daemon = True
        t.start()
        while True:
            try:
                sniff(iface=self.iface, prn=self.sniffer, count=2)
                time.sleep(0.01)
            except KeyboardInterrupt:
                print("\n")
                break

