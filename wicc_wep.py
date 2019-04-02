#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    WiCC (Wireless Cracking Camp)
    GUI tool for wireless cracking on WEP and WPA/WPA2 networks.
    Project developed by Pablo Sanz Alguacil and Miguel Yanes Fernández, as the Group Project for the 3rd year of the
    Bachelor of Sicence in Computing in Digital Forensics and CyberSecurity, at TU Dublin - Blanchardstown Campus
"""

from wicc_enc_type import EncryptionType
from time import sleep


class WEP(EncryptionType):
    def __init__(self, network, interface):
        EncryptionType.__init__(self, network, interface)
        # super().__init__(self, network, interface)

    def scan_network(self, write_directory):
        super(WEP, self).scan_network(write_directory)

        valid_handshake = False

        while not valid_handshake:
            valid_handshake = self.filter_pyrit_out()


    def crack_network(self):
        aircrack_cmd = ['aircrack-ng', '/tmp/WiCC/net_attack-01.cap.bak', '-b', self.bssid,
                        '>', '/tmp/WiCC/aircrack-out']
        crack_out, crack_err = super().execute_command(aircrack_cmd)
        # will need to filter the output from aircrack
        password = self.filter_aircrack(crack_out.decode('utf-8'))
        return password
