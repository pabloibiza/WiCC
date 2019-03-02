#!/usr/bin/env python3
"""
    WiCC (Wireless Cracking Camp)
    GUI tool for wireless cracking on WEP and WPA/WPA2 networks.
    Project developed by Pablo Sanz Alguacil and Miguel Yanes Fernández, as the Group Project for the 3rd year of the
    Bachelor of Sicence in Computing in Digital Forensics and CyberSecurity, at TU Dublin - Blanchardstown Campus
"""

import Operations
import Model
import ObjectList
import Interface
import time

#import subprocess
from subprocess import Popen, PIPE

class Control:
    model = ""
    selectedInterface = ""
    selectedNetwork = ""
    operations = ""


    def __init__(self):
        self.model = ""
        #self.model = Model.__init__(self)

    def check_software(self):
        # check installed software
        return 0

    def scan_interfaces(self):
        command = "iwconfig"
        process = Popen(command.split(), stdout=PIPE, stderr=PIPE)
        output, error = process.communicate()
        output = output.decode("utf-8")
        error = error.decode("utf-8")
        print("output: "+str(output))
        print("error: "+str(error))

        self.filter_interfaces(output)

        interfaces = ""  # get from command output
        #self.set_interfaces(interfaces)

    def filter_interfaces(self, str_interfaces):
        interfaces = str_interfaces.split('\n')
        name = ""
        address = ""
        type = ""
        power = 0
        channel = 0

        for line in interfaces:
            if line[:1] != " ":
                info = line.split(":")
                name = info[0]
                # print(name)
            else:
                info = line.split(':')
                if info[0] == "inet" or info[0] == "ether":
                    address = info[1]
                # elif info[0] ==


            new_interface = Interface.__init__()
        #print(interfaces)

    def set_interfaces(self, interfaces):
        self.model.set_interfaces(interfaces)

    def scan_networks(self):
        networks = ""  # get from command
        #self.set_networks(networks)

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
        exit = True
        time.sleep(1)
