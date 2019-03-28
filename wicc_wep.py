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
        super().__init__(self, network, interface)

    def scan_network(self):
        super().scan_network()
        valid_handshake = False

        pyrit_cmd = ['pyrit', '-r', '/tmp/WiCC/net_attack-01.cap.bak', 'analyse']
        de_auth_cmd = ['aireplay-ng', '-0', '1', '--ignore-negative-one', '-a', self.bssid, '-D', self.interface]

        second_iterator = 0 # when 15, de-auth's clients on the network
        while not valid_handshake:
            pyrit_out, err = super().execute_command(pyrit_cmd)
            valid_handshake = self.filter_pyrit_out(pyrit_out)
            if not valid_handshake:
                sleep(1)
                second_iterator += 1
                if second_iterator == 15:
                    super().execute_command(de_auth_cmd)
                    second_iterator = 0

    @staticmethod
    def filter_pyrit_out(output):
        for line in output:
            if line == 'No valid EAOPL-handshake + ESSID detected.':
                return False
        return True

    def crack_network(self):
        aircrack_cmd = ['aircrack-ng', '/tmp/WiCC/net_attack-01.cap.bak', '-b', self.bssid]
        crack_out, crack_err = super().execute_command()
        password = ""
        return password
