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
import time


class EncryptionType:

    def __init__(self, network, interface):
        self.target_network = network
        self.interface = interface
        self.bssid = network.get_bssid()
        self.essid = network.get_essid()[1:]  # [1:] is to remove an empty space before the name
        self.channel = str(int(self.target_network.get_channel()))

    @staticmethod
    def execute_command(command):
        """
        Generic method to execute a command using pipes
        :param command: list of words of the command to execute
        :return: output and error of the command execution

        :Author: Miguel Yanes Fernández
        """
        process = Popen(command, stdout=PIPE, stderr=PIPE)
        return process.communicate()

    def scan_network(self, write_directory):
        """

        :param write_directory:
        :return:
        """
        self.execute_command(['rm', '-r', write_directory])
        self.execute_command(['mkdir', write_directory])
        airmon_start_cmd = ['airmon-ng', 'start', self.interface, self.channel]
        airmon_check_cmd = ['airmon-ng', 'check', 'kill']
        airodump_scan_cmd = ['airodump-ng', self.interface + 'mon', '-a', '--bssid', self.bssid, '--write',
                             write_directory + 'net_attack', '--channel', self.channel, '--write-interval', '1']
        self.execute_command(airmon_start_cmd)
        self.execute_command(airmon_check_cmd)
        thread = threading.Thread(target=self.execute_command, args=(airodump_scan_cmd,))
        thread.start()
        thread.join(1)

        time.sleep(4)  # check if necessary

    @staticmethod
    def filter_pyrit_out(output):
        output = output.decode('utf-8')
        lines = output.split('\n')
        for line in lines:
            if line == 'No valid EAOPL-handshake + ESSID detected.':
                return False
            elif 'handshake(s)' in line:
                print("pyrit handshake: " + line)
                return True
        return False

    def check_cracking_status(self, file):
        return ""
        #print(file.decode('utf-8'))

    @staticmethod
    def filter_cowpatty_out(output):
        output = output.decode('utf-8')
        lines = output.split('\n')
        for line in lines:
            if line == 'End of pcap capture file, incomplete four-way handshake exchange.  ' \
                       'Try using a different capture.':
                return False
            elif 'mount crack' in line:
                print("cowpatty handshake: " + line)
                return True
        return False

    @staticmethod
    def filter_aircrack(output):
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
        return ""
