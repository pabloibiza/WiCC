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
from wicc_enc_type import EncryptionType
from wicc_wpa import WPA
from wicc_wep import WEP
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
    headless = False

    def __init__(self):
        self.model = ""
        self.model = Model()
        self.view = View(self)

    def start_view(self, headless):
        """
        Start the view windows
        :param headless: indicates whether the program will run headless
        :return:
        """
        self.view.build_window(headless)
        self.headless = headless

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

        if if_error is not None:
            w_interfaces = self.filter_interfaces(if_output)
        else:
            return

        # iw info
        interfaces = []
        for w_interface in w_interfaces:

            # command example: iw wlan0 info
            iw_output, iw_error = self.execute_command(['iw', w_interface, 'info'])
            iw_output = iw_output.decode("utf-8")
            iw_error = iw_error.decode("utf-8")

            iw_error = iw_error.split(':')
            # if there is no error, it is a wireless interface
            if iw_error[0] != "command failed":
                interfaces.append(self.filter_w_interface(iw_output))

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
                info = line.split(" ")
                info = info[0].split(":")

                name = info[0]
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
        str_iw_info = str_iw_info.split("\n")
        for lines in str_iw_info:
            # if last line
            if lines == "":
                break

            # reads the data from each line
            line = lines.split()
            if line[0] == "Interface":
                interface[0] = line[1]
            elif line[0] == "addr":
                interface[1] = line[1]
            elif line[0] == "type":
                interface[2] = line[1]
            elif line[0] == "txpower":
                interface[3] = line[1]
            elif line[0] == "channel":
                interface[4] = line[1]

        return interface

    def set_interfaces(self, interfaces):
        """
        Using the model instance, sets the interfaces passed as parameter. First checks if there are any new interfaces
        :param interfaces: list of instances of the object Interface
        :return: none
        """
        if not self.model.compare_interfaces(interfaces):
            for interface in interfaces:
                self.model.add_interface(interface[0], interface[1], interface[2], interface[3], interface[4])
            self.notify_view()


    def scan_networks(self):
        """
        Scan all the networks with airodump-ng. Executes the scan concurrently in a thread. Writes the output of the
        command to the file /tmp/WiCC/net_scan-01.csv
        This file is then passed to the method filter_networks
        :return: none
        """
        tempfile = "/tmp/WiCC/net_scan"
        self.execute_command(['rm', '-r', '/tmp/WiCC'])
        out, err = self.execute_command(['mkdir', '/tmp/WiCC'])

        # change wireless interface name to the parameter one

        command = ['airodump-ng', self.selectedInterface, '--write', tempfile, '--output-format', 'csv']
        thread = threading.Thread(target=self.execute_command, args=(command,))
        thread.start()
        thread.join(1)
        # out, err = self.execute_command(['timeout', '1', 'airodump-ng', 'wlan0'])

    def filter_networks(self):
        """
        Filters the input from the csv file (open the file and reads it)
        :param tempfile: directory for the csv file of the network scan
        :return: none
        """
        tempfile = "/tmp/WiCC/net_scan"
        #networks = self.filter_networks(tempfile)

        tempfile += '-01.csv'
        networks = []
        clients = []
        first_empty_line = False
        second_empty_line = False
        with open(tempfile, newline='') as csvfile:
            csv_reader = csv.reader(csvfile, delimiter=',')
            for row in csv_reader:

                if row == [] and not first_empty_line:
                    first_empty_line = True
                elif row == [] and not second_empty_line:
                    second_empty_line = True
                elif second_empty_line:
                    clients.append(row)
                else:
                    networks.append(row)

        self.set_networks(networks)
        self.set_clients(clients)
        self.notify_view()

    def set_networks(self, networks):
        """
        Using the model instance, sets the new scanned networks (all of them, overwriting the old ones)
        :param networks: list of instances of objects from the class Network
        :return: none
        """
        #for network in networks:
        #    for pair in network:

        self.model.set_networks(networks)

    def set_clients(self, clients):
        """
        Given a list of clients, tells the model to store them
        :param clients: list of parameters of clients
        :return:
        """
        self.model.set_clients(clients)

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
        if not self.headless:
            # if the program is not running headless, we notify the view
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
        elif operation == Operation.SELECT_NETWORK:
            self.selectedNetwork = value

    def attack_network(self):
        network_encryption = self.selectedNetwork.get_encryption()
        if network_encryption == 'WEP':
            wep_attack = WEP(self.selectedNetwork, self.selectedInterface)
            wep_attack.scan_network()
            password = wep_attack.crack_network()
        else:
            return
