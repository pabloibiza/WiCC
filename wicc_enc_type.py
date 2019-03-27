#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    WiCC (Wireless Cracking Camp)
    GUI tool for wireless cracking on WEP and WPA/WPA2 networks.
    Project developed by Pablo Sanz Alguacil and Miguel Yanes Fernández, as the Group Project for the 3rd year of the
    Bachelor of Sicence in Computing in Digital Forensics and CyberSecurity, at TU Dublin - Blanchardstown Campus
"""
from subprocess import Popen, PIPE


class EncryptionType:

    def __init__(self, network, interface):
        self.target_network = network
        self.interface = interface
        self.bssid = network.get_bssid()
        self.channel = self.target_network.get_channel()

    @staticmethod
    def execute_command(command):
        process = Popen(command, stdout=PIPE, stderr=PIPE)
        return process.communicate()

    def scan_network(self):
        write_directory = '/tmp/WiCC'
        self.execute_command(['rm', '-r', write_directory])
        self.execute_command(['mkdir', write_directory])

        airmon_start_cmd = ['airmon-ng', 'start', self.bssid, self.channel]
        airmon_check_cmd = ['airmon-ng', 'check', 'kill']
        airodump_scan_cmd = ['airodump-ng', self.interface, '--bssid', self.bssid, '--write', write_directory +
                             'net_attack', '--channel', self.channel]
        self.execute_command(airmon_start_cmd)
        self.execute_command(airmon_check_cmd)
        self.execute_command(airodump_scan_cmd)

    def crack_network(self):
        return 0
