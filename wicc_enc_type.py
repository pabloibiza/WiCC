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


class EncryptionType:

    def __init__(self, network, interface):
        self.target_network = network
        self.interface = interface
        self.bssid = network.get_bssid()
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
        airodump_scan_cmd = ['airodump-ng', self.interface + 'mon', '--bssid', self.bssid, '--write',
                             write_directory + 'net_attack', '--channel', self.channel]
        self.execute_command(airmon_start_cmd)
        self.execute_command(airmon_check_cmd)
        thread = threading.Thread(target=self.execute_command, args=(airodump_scan_cmd,))
        thread.start()
        thread.join(1)
