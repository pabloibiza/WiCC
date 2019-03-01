#!/usr/bin/env python3
"""
    WiCC (Wireless Cracking Camp)
    GUI tool for wireless cracking on WEP and WPA/WPA2 networks.
    Project developed by Pablo Sanz Alguacil and Miguel Yanes Fernández, as the Group Project for the 3rd year of the
    Bachelor of Sicence in Computing in Digital Forensics and CyberSecurity, at TU Dublin - Blanchardstown Campus
"""

import Operations
import Model
import time



class Control:
    model = ""
    selectedInterface = ""
    selectedNetwork = ""
    operations = ""

    def __init__(self):
        self.model = Model.__init__(self)

    def scan_interfaces(self):
        interfaces = ""  # get from command output
        self.set_interfaces(interfaces)

    def set_interfaces(self, interfaces):
        self.model.set_interfaces(interfaces)

    def scan_networks(self):
        networks = ""  # get from command
        self.set_networks(networks)

    def set_networks(self, networks):
        self.model.set_networks(networks)

    def has_selected_interface(self):
        return self.selectedInterface != ""

    def has_selected_network(self):
        return self.selectedNetwork != ""

    def get_notify(self, operation, value):
        return 0


if __name__ == '__main__':
    control = Control()
    exit = False

    while not exit:
        if control.has_selected_interface():
            control.scan_networks()
        else:
            control.scan_interfaces()

        time.sleep(1)
