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
import sys

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
    allows_monitor = False  # to know if the wireless interface allows monitor mode
    scan_stopped = False  # to know if the network scan is running
    running_stopped = False  # to know if the program is running (or if the view has been closed)
    scan_filter_parameters = ["", ""]

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
        software = [False, False, False]
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

        return software, some_missing

    def check_monitor_mode(self):
        """
        Checks if the selected interface supports monitor mode
        :return: whether the selected interface supports monitor mode
        """
        iw_cmd = ['iw', 'list']
        iw_out, iw_err = self.execute_command(iw_cmd)

        iw_out = iw_out.decode('utf-8')
        lines = iw_out.split('\n')
        for line in lines:
            words = line.split(' ')
            for word in words:
                if word == 'monitor':
                    self.allows_monitor = True
                    return
        self.view.show_info_notification("The selected interface doesn't support monitor mode, "
                                         "which is highly recommended."
                                         "\nYou can run the program anyways but "
                                         "may be missing some functionalities")

    def scan_interfaces(self, auto_select):
        """
        Scans all network interfaces. After filtering them (method filter_interfaces,
        scans available wireless interfaces. Finally calls the method filter_w_interface
        :param auto_select: whether the interface should be selected automatically
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
                if auto_select:
                    self.selectedInterface = self.filter_w_interface(iw_output)[0]

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

        self.check_monitor_mode()

        tempfile = "/tmp/WiCC/net_scan"
        self.execute_command(['rm', '-r', '/tmp/WiCC'])
        out, err = self.execute_command(['mkdir', '/tmp/WiCC'])

        # change wireless interface name to the parameter one

        if self.allows_monitor:
            airmon_cmd = ['airmon-ng', 'start', self.selectedInterface]
            interface = self.selectedInterface + 'mon'
            self.execute_command(airmon_cmd)
        else:
            interface = self.selectedInterface

        command = ['airodump-ng', interface, '--write', tempfile, '--output-format', 'csv']
        if (self.scan_filter_parameters[0] != "ALL"):
            command.append('--encrypt')
            command.append(self.scan_filter_parameters[0])
        if (self.scan_filter_parameters[1] != "ALL"):
            command.append('--channel')
            command.append(self.scan_filter_parameters[1])
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
        # networks = self.filter_networks(tempfile)

        tempfile += '-01.csv'
        networks = []
        clients = []
        first_empty_line = False
        second_empty_line = False
        try:
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
            return
        except:
            # This exception is usually caused by the wireless interface already running in monitor mode.
            # Therefore, a probable fix is to stop the card to run in monitor mode with: airmon-ng stop
            out, err = self.execute_command(['airmon-ng', 'stop', self.selectedInterface])
            self.execute_command(['NetworkManager'])
            exception_msg = "Error while accessing temporary dump files"
            if err == b'':
                # if there is no error when resetting the wireless card
                exception_msg += "\n\nThe error may be fixed automatically. " \
                                 "Please close this window and restart the program"
            else:
                # if there is an error when resetting the wireless card. The users must solve this by themselves.
                exception_msg += "\n\nThe error couldn't be fixed automatically. Please reconnect or reconfigure " \
                                 "your wireless card. Make sure it's not running in monitor mode"
            self.view.show_warning_notification(exception_msg)
            sys.exit(1)

    def set_networks(self, networks):
        """
        Using the model instance, sets the new scanned networks (all of them, overwriting the old ones)
        :param networks: list of instances of objects from the class Network
        :return: none
        """
        # for network in networks:
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
        if not self.headless and not self.run_stopped():
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
            self.stop_scan()
            self.attack_network()
        elif operation == Operation.ATTACK_NETWORK:
            # USELESS right now
            self.stop_scan()
            self.attack_network()
        elif operation == Operation.STOP_SCAN:
            self.stop_scan()
        elif operation == Operation.STOP_RUNNING:
            self.stop_scan()
            self.view.reaper_calls()
            self.running_stopped = True
            # sys.exit(0)
        elif operation == Operation.SCAN_OPTIONS:
            self.apply_filters(value)
        elif operation == Operation.CUSTOMIZE_MAC:
            self.customize_mac(value)
        elif operation == Operation.RANDOMIZE_MAC:
            self.randomize_mac(value)
        elif operation == Operation.RESTORE_MAC:
            self.restore_mac(value)
        elif operation == Operation.SPOOF_MAC:
            pass
        elif operation == Operation.CHECK_MAC:
            self.mac_checker(value)

    def apply_filters(self, value):
        """
        Sets the parameters channel and encryption to scan, and clients and wps for post-scanning filtering
        scan_filter_parameters[0] = encryption
        scan_filter_parameters[1] = channel
        :param: value: array containing the parameters [encryption, wps, clients, channel]
        :return: none
        :author: Pablo Sanz
        """
        self.scan_filter_parameters[0] = value[0]
        self.scan_filter_parameters[1] = value[3]
        self.model.get_filters(value[1], value[2])

    def stop_scan(self):
        pgrep_cmd = ['pgrep', 'airodump-ng']
        pgrep_out, pgrep_err = self.execute_command(pgrep_cmd)

        pgrep_out = pgrep_out.decode('utf-8')

        if pgrep_out != "":
            pids = pgrep_out.split('\n')
            for pid in pids:
                self.execute_command(['kill', '-9', pid])  # kills all processes related with airodump
            self.scan_stopped = True
            if self.allows_monitor:
                airmon_cmd = ['airmon-ng', 'stop', self.selectedInterface + 'mon']  # stop card to be in monitor mode
                ifconf_up_cmd = ['ifconfig', self.selectedInterface, 'up']  # sets the wireless interface up again
                net_man_cmd = ['NetworkManager']  # restarts NetworkManager

                self.execute_command(airmon_cmd)
                self.execute_command(ifconf_up_cmd)
                self.execute_command(net_man_cmd)

    def get_interfaces(self):
        return self.model.get_interfaces()

    def attack_network(self):
        network = self.model.search_network(self.selectedNetwork)
        network_encryption = network.get_encryption()
        time.sleep(0.01)
        if network_encryption == ' WEP':
            print("wep attack")
            wep_attack = WEP(network, self.selectedInterface)
            wep_attack.scan_network()
            password = wep_attack.crack_network()
            print("Password (?): " + password)
            self.stop_scan()
            # wep_attack.finish_attack()
        elif network_encryption[:4] == " WPA":
            wpa_attack = WPA(network, "rockyou.txt")
            # wpa_attack.scan_network()
            password = wpa_attack.crack_network()

    def running_scan(self):
        return not self.scan_stopped

    def run_stopped(self):
        return self.running_stopped

    def randomize_mac(self, interface):
        command1 = ['ifconfig', interface, 'down']
        command2 = ['macchanger', '-r', interface]
        command3 = ['ifconfig', interface, 'up']
        self.execute_command(command1)
        self.execute_command(command2)
        self.execute_command(command3)

    def customize_mac(self,values):
        """
        :param values: 0 - interface, 1 - mac address
        :return:
        """
        print("###################################\n" + values[0] + values[1] + "##################################")
        command1 = ['ifconfig', values[0], 'down']
        command2 = ['macchanger', '-m', values[1], values[0]]
        command3 = ['ifconfig', values[0], 'up']
        self.execute_command(command1)
        self.execute_command(command2)
        self.execute_command(command3)

    def restore_mac(self, interface):
        command1 = ['ifconfig', interface, 'down']
        command2 = ['macchanger', '-p', interface]
        command3 = ['ifconfig', interface, 'up']
        self.execute_command(command1)
        self.execute_command(command2)
        self.execute_command(command3)

    def mac_checker(self, interface):
        try:
            command1 = ['macchanger', '-s', interface]
            p = Popen(command1, stdout=PIPE, stderr=PIPE)
            (output, err) = p.communicate()
            output = output.decode("utf-8")
            line = output.split(" ")[4]
            return line
        except:
            self.view.show_warning_notification("Can't show current MAC adress")
            return False
