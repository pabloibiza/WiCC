#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    WiCC (Wireless Cracking Camp)
    GUI tool for wireless cracking on WEP and WPA/WPA2 networks.
    Project developed by Pablo Sanz Alguacil and Miguel Yanes Fernández, as the Group Project for the 3rd year of the
    Bachelor of Sicence in Computing in Digital Forensics and CyberSecurity, at TU Dublin - Blanchardstown Campus
"""


import os, sys
import Operations
import Model
import ObjectList
import Interface
import time

import csv

from subprocess import Popen, PIPE
import threading

class Control:
    model = ""
    selectedInterface = ""
    selectedNetwork = ""
    operations = ""


    def __init__(self):
        self.model = ""
        #self.model = Model.__init__(self)


    def execute_command(self, command):
        process = Popen(command, stdout=PIPE, stderr=PIPE)
        return process.communicate()

    def check_software(self):
        # check installed software
        # ifconfig, aircrack-ng, pyrit, cowpatty
        software = [False, False, False, False]
        some_missing = False
        # ifconfig
        out, err = self.execute_command(['which', 'ifconfig'])

        if int.from_bytes(out, byteorder="big") != 0:
            software[0] = True
        else:
            some_missing = True
        # aircrack-ng
        out, err = self.execute_command(['which', 'aircrack-ng'])

        if int.from_bytes(out, byteorder="big") != 0:
            software[1] = True
        else:
            some_missing = True

        # pyrit
        out, err = self.execute_command(['which', 'pyrit'])

        if int.from_bytes(out, byteorder="big") != 0:
            software[2] = True
        else:
            some_missing = True

        # cowpatty
        out, err = self.execute_command(['which', 'cowpatty'])

        if int.from_bytes(out, byteorder="big") != 0:
            software[3] = True
        else:
            some_missing = True

        return software, some_missing

    def scan_interfaces(self):
        # ifconfig
        if_output, if_error = self.execute_command("ifconfig")
        if_output = if_output.decode("utf-8")
        if_error = if_error.decode("utf-8")
        print("Interfaces:\noutput: "+str(if_output))
        print("error: "+str(if_error))

        if if_error != None:
            w_interfaces = self.filter_interfaces(if_output)
        else:
            return

        # iw info
        for w_interface in w_interfaces:
            print("Wireless interface: " + w_interface)

            # command: iw wlan0 info
            iw_output, iw_error = self.execute_command(['iw', w_interface, 'info'])
            iw_output = iw_output.decode("utf-8")
            iw_error = iw_error.decode("utf-8")
            print("\n\nWireless interfaces\noutput: " + str(iw_output))
            print("error: " + str(iw_error))

            iw_error = iw_error.split(':')
            # if there is no error, it is a wireless interface
            if iw_error[0] != "command failed":
                print("W if: " + iw_output)
                interface = self.filter_w_interface(iw_output)
                self.selectedInterface = interface
                # self.model.add_interface(interface)

    # Filters the input for all network interfaces, returns array of names of all interfaces
    def filter_interfaces(self, str_ifconfig):
        interfaces = str_ifconfig.split('\n')
        w_interfaces = []

        for line in interfaces:
            if line[:1] != " " and line[:1] != "":
                info = line.split(":")
                name = info[0]
                print("Name: " + name)
                w_interfaces.append(name)
        return w_interfaces

    # Filters the input for a single wireless interfaces, returns array with interface parameters
    def filter_w_interface(self, str_iw_info):
        # Interface: name address type power channel
        interface = ["", "", "", 0, 0]
        print("str_iw_info: " + str_iw_info)
        str_iw_info = str_iw_info.split("\n")
        print("str_iw_info: " + str_iw_info[0])
        for lines in str_iw_info:
            print("LINES: " + lines)
            # if last line
            if lines == "":
                print("none")
                break

            # reads the data from each line
            line = lines.split()
            if line[0] == "Interface":
                interface[0] = line[1]
                print("name set")
            elif line[0] == "addr":
                interface[1] = line[1]
                print("addr set")
            elif line[0] == "type":
                interface[2] = line[1]
                print("type set")
            elif line[0] == "txpower":
                interface[3] = line[1]
                print("power set")
            elif line[0] == "channel":
                interface[4] = line[1]
                print("channel set")
        print("******Interfaces:")
        for i in interface:
            print(i)

        return interface

    def set_interfaces(self, interfaces):
        self.model.set_interfaces(interfaces)

    def scan_networks(self):
        print("**********************\n\tScan networks\n")
        tempfile = "/tmp/WiCC/net_scan"
        self.execute_command(['rm', '-r', '/tmp/WiCC'])
        out, err = self.execute_command(['mkdir', '/tmp/WiCC'])
        print(err)
        # change wireless interface name to the parameter one

        # TEMPORARILY with a timeout
        # MODIFY TO IMPLEMENT CONCURRENCY FOR PROTOTYPE 2
        # execute airodump-ng with a timeout of 5 seconds
        print("start airodump ...")
        command = ['airodump-ng', 'wlan0', '--write', tempfile, '--output-format', 'csv']
        thread = threading.Thread(target=self.execute_command, args=(command,))
        thread.start()
        thread.join(1)
        #out, err = self.execute_command(['timeout', '1', 'airodump-ng', 'wlan0'])
        print("finish airodump\n*********************\nstart network filtering")
        self.filter_networks(tempfile)
        #print(out)
        #print(err)
        networks = ""  # get from command
        #self.set_networks(networks)

    def filter_networks(self, tempfile):
        tempfile += '-01.csv'

        with open(tempfile, newline='') as csvfile:
            print("csv open")
            csv_reader = csv.reader(csvfile, delimiter=',')
            print(csv_reader)
            for row in csv_reader:
                print(", ".join(row))


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
    # check root privilege
    if os.getuid() != 0:
        print("\n\tError: script must be executed as root\n")
        sys.exit(1)

    # checks python version
    if sys.version_info[0] < 3:
        print("\n\tError: Must be executed with Python 3\n")
        sys.exit(1)

    control = Control()
    exit = False

    software, some_missing = control.check_software()
    if some_missing:
        print("The required software is not installed:\n")
        for i in range (0, len(software)):
            if software[i] == False:
                if i == 0:
                    print("\t***Missing ifconfig")
                elif i == 1:
                    print("\t***Missing aircrack-ng")
                elif i == 2:
                    print("\t***Missing pyrit")
                elif i == 3:
                    print("\t***Missing cowpatty")

        print("\n")
        sys.exit(1)

    while not exit:
        if control.has_selected_interface():
            control.scan_networks()
            # Process(target=control.scan_networks()).start()
            #scan_process.start()
            #scan_process.join()
            print("scanning networks")
            print("filtering networks")
            time.sleep(3)
            while not control.selectedNetwork != "":
                time.sleep(1)
                print("**************************************************\n****************start filtering*******************\n**************************************************")
                control.filter_networks("/tmp/WiCC/net_scan")
            sys.exit(0)
        else:
            control.scan_interfaces()
        time.sleep(1)
