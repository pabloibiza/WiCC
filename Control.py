#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    WiCC (Wireless Cracking Camp)
    GUI tool for wireless cracking on WEP and WPA/WPA2 networks.
    Project developed by Pablo Sanz Alguacil and Miguel Yanes Fernández, as the Group Project for the 3rd year of the
    Bachelor of Sicence in Computing in Digital Forensics and CyberSecurity, at TU Dublin - Blanchardstown Campus
"""


import sys
import Operations
import Model
import ObjectList
import Interface
import time

#import subprocess
from subprocess import Popen, PIPE, check_output, STDOUT

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
        # ifconfig
        #command = "ip -o link show | awk -F': ' '{print $2}'"
        #process = Popen(command.split(), stdout=PIPE, stderr=PIPE)
        ip = "ip -o link show"
        awk = "awk -F': ' '{print $2}'"
        ip_command = Popen(ip.split(), stdout=PIPE)
        awk_command = Popen(["awk", "-F", "': '", "'{print $2}'"], stdin=ip_command.stdout, stdout=PIPE)

        if_output, if_error = awk_command.communicate()
        if_output = if_output.decode("utf-8")
        if_error = if_error.decode("utf-8")
        print("Interfaces:\noutput: "+str(if_output))
        print("error: "+str(if_error))

        # iwconfig
        w_command = "iw wlan0 info"
        w_process = Popen(w_command.split(), stdout=PIPE, stderr=PIPE)
        iw_output, iw_error = w_process.communicate()
        iw_output = iw_output.decode("utf-8")
        iw_error = iw_error.decode("utf-8")
        print("\n\nWireless interfaces\noutput: " + str(iw_output))
        print("error: " + str(iw_error))

        # self.filter_interfaces(if_output, iw_output)

        interfaces = ""  # get from command output
        #self.set_interfaces(interfaces)

    def filter_interfaces(self, str_ifconfig, str_iwconfig):
        interfaces = str_ifconfig.split('\n')
        w_interfaces = str_iwconfig.split('\n')
        name = ""
        address = ""
        type = ""
        power = 0
        channel = 0

        for line in interfaces:
            if line[:1] != " " and line[:1] != "":
                info = line.split(":")
                name = info[0]
                print("Name: " + name)
            else:
                info = line.split(' ')
                if info[0] == "inet" or info[0] == "ether":
                    address = info[1]
                    print("Address: " + address)
                # elif info[0] ==

            # if end of the interface
            if False: #line[:] == "":
                # filter wireless interface
                for w_line in w_interfaces:
                    if w_line == "no wireless extensions.":
                        print ("no wireless extensions")
                        break
                    else:
                        wireless = w_line.split(' ')
                        if wireless[0] == name:
                            print ("asdasd" + wireless[1])
                        else:
                            break
                        interface = Interface(name, address, type, power, channel)
                        self.set_interfaces(interface)
                        name = ""
                        address = ""
                        type = ""
                        power = 0
                        channel = 0
                break


            #new_interface = Interface.__init__()
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


# Execute from command line, not from IDE
if __name__ == '__main__':
    # checks python version
    if sys.version_info[0] < 3:
        print("\n\tMust be executed with Python 3\n")
        sys.exit(1, "Unsupported Python version")

    control = Control()
    exit = False

    while not exit:
        if control.has_selected_interface():
            control.scan_networks()
        else:
            control.scan_interfaces()
        exit = True # delete after interfaces tests
        time.sleep(1)
