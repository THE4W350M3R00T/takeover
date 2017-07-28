# Takeover
### Made by koreX and Harrig
Takeover is a networking attacking tool for pentesters. It's a powerful tool which can perform attacks, reconnaissance, spoofing, social engineering, sniffing and much more.

## Installation:

To install the TakeOver stable release version type the following command in your terminal:

`
git clone https://github.com/THE4W350M3R00T/takeover
`


## Usage:

After installation go to the takeover directory:

`
cd takeover
`


For a list of commands type the following:

`
python3 takeover.py --help
`

or

`
python3 takeover.py -h
`

"""
commands here
"""

### Example commands:

`
python3 takeover.py --wlansniffer --interface wlan0mon
`

This will show all nearby Access Points with BSSID, ESSID, Channel and encryption type

`
python3 takeover.py --DoS pingflood --target 127.0.0.1 --threads 10
`

This will launch a pingflood DoS attack on target 127.0.0.1 with 10 threads

`
python3 takeover.py --spoof ARP -t 192.168.1.8 -g 192.168.1.1
`

This will launch an ARP spoof attack a.k.a. MITM attack with target 192.168.1.8 and gateway 192.168.1.1 (Specifying gateway IP is optional)

`
python3 takeover.py --deauth --target 12:AB:34:CD:56:EF
`

This will launch a deauth attack on target 12:AB:34:CD:56:EF (BSSID of the access point)
