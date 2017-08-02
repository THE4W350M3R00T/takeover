import os
from lib.colors import *
import logging
import netifaces

class monitorMode(object):

    def __init__(self):
        self.__interface = None

    def interface(self, iface):
        self.__interface = iface
        return self.__interface

    def enable_air(self):
        cmd = os.system("airmon-ng check kill")
        if cmd == 32512:
            return False
        os.system("airmon-ng start {}".format(self.__interface))
        return True

    def disable_air(self):
        os.system("airmon-ng stop {}".format(self.__interface))

    def enable_iw(self):
        os.system("ifconfig {} down".format(self.__interface))
        os.system("iwconfig {} mode monitor".format(self.__interface))
        os.system("ifconfig {} up".format(self.__interface))

    def disable_iw(self):
        os.system("ifconfig {} down".format(self.__interface))
        os.system("iwconfig {} mode managed".format(self.__interface))
        os.system("ifconfig {} up".format(self.__interface))

    def Main(self):
        if not self.enable_air():
            self.enable_iw()
        else:
            return True

class interfaces(monitorMode):

    def __init__(self):
        self._ifaces = None

    def get_ifaces(self):
        self._ifaces = netifaces.interfaces()
        return self._ifaces
        
    def get_wlan(self):
        ifaces = self.get_ifaces()
        for iface in ifaces:
            if iface.endswith("mon"):
                return [iface, True]
            elif iface.startswith("wl") or iface.startswith("ath") and not iface.endswith("mon"):
                self.interface(iface)
                return [iface, False]
        return None

    def checking(self):
        if self.get_wlan() == None:
            for x, y in enumerate(self._ifaces):
                print("[{2}{0}{3}] {4}{1}{3}".format(x+1, y, LRED, RST, RD))
            choose = int(input("\nSelect your wireless interface: "))
            if choose > len(self._ifaces) or 1 > choose:
                print("Choose one of the numbers")
                os._exit(1)
            self.interface(self._ifaces[choose-1])
            self.Main()
            return self._ifaces[choose-1] + "mon"
        try:
            wlaniface = self.get_wlan()
            if wlaniface[1] == True:
                return wlaniface[0]
            elif wlaniface[1] == False:
                self.Main()
                return wlaniface[0] + "mon"
        except:
            pass
 
