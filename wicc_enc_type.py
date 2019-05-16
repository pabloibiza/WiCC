#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    WiCC (Wireless Cracking Camp)
    GUI tool for wireless cracking on WEP and WPA/WPA2 networks.
    Project developed by Pablo Sanz Alguacil and Miguel Yanes Fernández, as the Group Project for the 3rd year of the
    Bachelor of Sicence in Computing in Digital Forensics and CyberSecurity, at TU Dublin - Blanchardstown Campus
"""
from subprocess import Popen, PIPE
import threading
import datetime


class EncryptionType:

    injection_supported = True  # to know if the interface supports packet injection
    timestamp = 0

    def __init__(self, network, interface, verbose_level, silent_attack, write_directory):
        """
        Construction for the parent class EncryptionType.
        :param network: target network
        :param interface: selected wireless interface
        :param verbose_level: verbose level set by main

        :Author: Miguel Yanes Fernández
        """
        self.target_network = network
        self.interface = interface
        self.bssid = network.get_bssid()
        self.essid = network.get_essid()[1:]  # [1:] is to remove an empty space before the name
        self.channel = str(int(self.target_network.get_channel()))
        self.verbose_level = verbose_level
        self.silent_attack = silent_attack
        print(silent_attack)
        self.write_directory = write_directory
        self.password = ""

    def show_message(self, message):
        """
        Prints a message if the verbose level is equal or higher than 2
        :param message: message to print
        :return: none

        :Author: Miguel Yanes Fernández
        """
        if self.verbose_level >= 2:
            print(message)

    def execute_command(self, command):
        """
        Static method to execute a defined command.
        :param command: parameters for the command. Should be divided into an array. EX: ['ls, '-l']
        :return: returns both stdout and stderr from the command execution

        :Author: Miguel Yanes Fernández
        """
        if self.verbose_level == 3:
            output = "[Command]:  "
            for word in command:
                output += word + " "
            self.show_message("\033[1;30m" + output + "\033[0m")

        process = Popen(command, stdout=PIPE, stderr=PIPE)
        return process.communicate()

    def scan_network(self):
        """
        Scans the target network and writes the dump file in the selected directory
        :param write_directory: directory to write the dump file
        :return: none

        :Author: Miguel Yanes Fernández
        """
        self.timestamp = int(datetime.datetime.now().timestamp()*1000000)

        #if self.write_directory[:5] == '/tmp/':
        #    self.execute_command(['rm', '-r', self.write_directory])
        #self.execute_command(['mkdir', self.write_directory])
        airmon_start_cmd = ['airmon-ng', 'start', self.interface, self.channel]
        self.interface += 'mon'
        airmon_check_cmd = ['airmon-ng', 'check', 'kill']
        airodump_scan_cmd = ['airodump-ng', self.interface, '-a', '--bssid', self.bssid, '--write',
                             self.write_directory + '/net_attack_' + str(self.timestamp), '--channel', self.channel,
                             '--write-interval', '2', '--output-format', 'pcap']
        self.execute_command(airmon_start_cmd)
        self.execute_command(airmon_check_cmd)
        thread = threading.Thread(target=self.execute_command, args=(airodump_scan_cmd,))
        thread.start()
        thread.join(1)

    def aireplay_check_injection(self, output):
        """
        Filters the output from aireplay to check if the interface allows packet injection
        :param output: output from the aireplay -9 command
        :return: true or false wether it allows packet injection
        """
        output = output.decode('utf-8')
        lines = output.split('\n')
        for line in lines:
            if 'Injection is working!' in line:
                return True
        self.silent_attack = True
        self.injection_supported = False
        self.show_message("Selected interface doesn't support packet injection")
        return False

    def get_injection_supported(self):
        return self.injection_supported

    def check_cracking_status(self, file):
        """
        Checks the status of the password cracking process given a file with the output from aircrack
        :param file: directory of the file with the aircrack output
        :return: tbd

        :Author: Miguel Yanes Fernández
        """
        return ""
        #print(file.decode('utf-8'))

    def filter_aircrack(self, output):
        """
        Filter the aircrack output to read the password (if any is found)
        :param output: output from the aicrack command
        :return: password (or "" if it wasn't found)

        :Author: Miguel Yanes Fernández
        """
        words = output.split(" ")
        next_1 = False
        next_2 = False
        for word in words:
            if word[:6] == "FOUND!":
                next_1 = True
            elif next_1:
                if not next_2:
                    next_2 = True
                else:
                    return word
        print(output)
        self.show_message("No password found in the capture file")
        return ""
