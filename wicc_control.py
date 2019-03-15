#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    WiCC (Wireless Cracking Camp)
    GUI tool for wireless cracking on WEP and WPA/WPA2 networks.
    Project developed by Pablo Sanz Alguacil and Miguel Yanes Fernández, as the Group Project for the 3rd year of the
    Bachelor of Sicence in Computing in Digital Forensics and CyberSecurity, at TU Dublin - Blanchardstown Campus
"""


import os, sys
from wicc_operations import Operation
from wicc_model import Model
from wicc_view import View
from wicc_interface import Interface
from wicc_network import  Network
import time

import csv

from subprocess import Popen, PIPE
import threading


class Control:
    model = ""
    view = ""
    selectedInterface = ""
    selectedNetwork = ""
    operations = ""

    def __init__(self):
        self.model = ""
        self.model = Model()
        self.view = View(self)

    def start_view(self):
        """
        Start the view windows
        :return:
        """
        self.view.build_window()

    @staticmethod
    def execute_command(command):
        """
        Static method to execute a defined command.
        :param command: parameters for the command. Should be divided into an array. EX: ['ls, '-l']
        :return: returns both stdout and stderr from the command execution
        """
        process = Popen(command, stdout=PIPE, stderr=PIPE)
        return process.communicate()

    def check_software(self):
        """
        Check whether the required software is installed or not.
        :return: list of software (array of booleans), and a boolean to say if any is missing
        """
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
        """
        Scans all network interfaces. After filtering them (method filter_interfaces,
        scans available wireless interfaces. Finally calls the method filter_w_interface
        :return: none
        """
        # ifconfig
        if_output, if_error = self.execute_command("ifconfig")
        if_output = if_output.decode("utf-8")
        if_error = if_error.decode("utf-8")
        print("Interfaces:\noutput: "+str(if_output))
        print("error: "+str(if_error))

        if if_error is not None:
            w_interfaces = self.filter_interfaces(if_output)
        else:
            return

        # iw info
        interfaces = []
        for w_interface in w_interfaces:
            print("Wireless interface: " + w_interface)

            # command example: iw wlan0 info
            iw_output, iw_error = self.execute_command(['iw', w_interface, 'info'])
            iw_output = iw_output.decode("utf-8")
            iw_error = iw_error.decode("utf-8")
            print("\n\nWireless interfaces\noutput: " + str(iw_output))
            print("error: " + str(iw_error))

            iw_error = iw_error.split(':')
            # if there is no error, it is a wireless interface
            if iw_error[0] != "command failed":
                print("W if: " + iw_output)
                interfaces.append(self.filter_w_interface(iw_output))
                self.selectedInterface = interfaces[0][0]

        self.set_interfaces(interfaces)

    @staticmethod
    def filter_interfaces(str_ifconfig):
        """
        Filters the input for all network interfaces
        :param str_ifconfig: string taken from the command execution stdout
        :return: array of names of all network interfaces
        """
        interfaces = str_ifconfig.split('\n')
        names_interfaces = []

        for line in interfaces:
            if line[:1] != " " and line[:1] != "":
                info = line.split(":")
                name = info[0]
                print("Name: " + name)
                names_interfaces.append(name)
        return names_interfaces

    @staticmethod
    def filter_w_interface(str_iw_info):
        """
        Filters the input for a single wireless interface. First checks if the interface is wireless
        :param str_iw_info: stdout for the command to see the wireless interfaces
        :return: array with the Interface parameters
        """
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
        """
        Using the model instance, sets the interfaces passed as parameter. First checks if there are any new interfaces
        :param interfaces: list of instances of the object Interface
        :return: none
        """
        if not self.model.compare_interfaces(interfaces):
            print("\tdifferent")
            for interface in interfaces:
                self.model.add_interface(interface[0], interface[1], interface[2], interface[3], interface[4])
            self.notify_view()
        else:
            print("\tequals")

    def scan_networks(self):
        """
        Scan all the networks with airodump-ng. Executes the scan concurrently in a thread. Writes the output of the
        command to the file /tmp/WiCC/net_scan-01.csv
        This file is then passed to the method filter_networks
        :return: none
        """
        print("**********************\n\tScan networks\n")
        tempfile = "/tmp/WiCC/net_scan"
        self.execute_command(['rm', '-r', '/tmp/WiCC'])
        out, err = self.execute_command(['mkdir', '/tmp/WiCC'])
        print(err)
        # change wireless interface name to the parameter one

        print("start airodump ...")
        command = ['airodump-ng', self.selectedInterface, '--write', tempfile, '--output-format', 'csv']
        thread = threading.Thread(target=self.execute_command, args=(command,))
        thread.start()
        thread.join(1)
        # out, err = self.execute_command(['timeout', '1', 'airodump-ng', 'wlan0'])
        print("finish airodump\n*********************\nstart network filtering")
        # print(out)
        # print(err)
        networks = ""  # get from command
        # self.set_networks(networks)

    def filter_networks(self):
        """
        Filters the input from the csv file (open the file and reads it)
        :param tempfile: directory for the csv file of the network scan
        :return: none
        """
        tempfile = "/tmp/WiCC/net_scan"
        #networks = self.filter_networks(tempfile)
        print("----set networks---")

        tempfile += '-01.csv'
        networks = []
        first_empty_line = False
        with open(tempfile, newline='') as csvfile:
            print("csv open")
            csv_reader = csv.reader(csvfile, delimiter=',')
            print(csv_reader)
            for row in csv_reader:
                networks.append(row)
        self.set_networks(networks)

    def set_networks(self, networks):
        """
        Using the model instance, sets the new scanned networks (all of them, overwriting the old ones)
        :param networks: list of instances of objects from the class Network
        :return: none
        """
        #for network in networks:
        #    for pair in network:

        self.model.set_networks(networks)
        self.notify_view()

    def has_selected_interface(self):
        """
        Method to check if there is a selected wireless interface
        :return: true or false whether the selected interface exists or is null
        """
        return self.selectedInterface != ""

    def has_selected_network(self):
        """
        Method to check if there is a selected network to attack
        :return:  true or false whether the selected network exists or is null
        """
        return self.selectedNetwork != ""

    def notify_view(self):
        """
        Send notify to update the view with the list of interfaces and networks
        :return:
        """
        interfaces, networks = self.model.get_parameters()
        self.view.get_notify(interfaces, networks)

    def get_notify(self, operation, value):
        """
        Receives the notify generated by the view
        :param operation: type of operation (from the enumeration class Operation)
        :param value: value applied to that operation
        :return:
        """
        if operation == Operation.SELECT_INTERFACE:
            self.selectedInterface = value
            print("Updated selected interface: " + str(value))
        elif operation == Operation.SELECT_NETWORK:
            self.selectedNetwork = value

