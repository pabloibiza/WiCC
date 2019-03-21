#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    WiCC (Wireless Cracking Camp)
    GUI tool for wireless cracking on WEP and WPA/WPA2 networks.
    Project developed by Pablo Sanz Alguacil and Miguel Yanes Fernández, as the Group Project for the 3rd year of the
    Bachelor of Sicence in Computing in Digital Forensics and CyberSecurity, at TU Dublin - Blanchardstown Campus
"""

from wicc_enc_type import EncryptionType


class WEP(EncryptionType):
    def __init__(self, network, interface):
        super().__init__(self, network, interface)

    def scan_network(self):
        super().scan_network()
        valid_handshake = False

        pyrit_cmd = ['pyrit', '-r', '/tmp/WiCC/net_attack-01.cap.bak', 'analyse']

        while not valid_handshake:
            pyrit_out, err = super().execute_command(pyrit_cmd)
            valid_handshake = self.filter_pyrit_out(pyrit_out)

    def filter_pyrit_out(self, output):
        line_num = 0
        for line in output:
            parameter = line.split(' ')

            for pair in parameter:
                if pair == self.target_network.get_bssid():
                    print('asd')

            line_num += 1

        return 0

    def crack_network(self):
        password = ""
        return password
