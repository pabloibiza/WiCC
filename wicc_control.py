#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    WiCC (Wifi Cracking Camp)
    GUI tool for wireless pentesting on WEP and WPA/WPA2 networks.
    Project developed by Pablo Sanz Alguacil, Miguel Yanes Fernández and Adan Chalkley,
    as the Group Project for the 3rd year of the Bachelor of Sicence in Computing in Digital Forensics and CyberSecurity
    at TU Dublin - Blanchardstown Campus
"""

from wicc_operations import Operation
from wicc_model import Model
from wicc_view import View
from wicc_wpa import WPA
from wicc_wep import WEP
from wicc_view_popup import PopUpWindow

from subprocess import Popen, PIPE

import time
import random
import os
import csv
import threading
import datetime


class Control:

    model = ""  # reference of the Model object (for the MVC communication)
    view = ""   # reference of the View object (for the MVC communication)
    operations = ""  # reference of the Operation object (for the operation notifies with View)
    popup = ""  # PopupWindow object to create all different popups

    selected_interface = ""  # selected interface by the user
    last_selectedInterface = ""  # last selected interface, will be used in the auto-select mode
    selected_network = ""  # selected target network for the attack/scan
    informational_popups = True  # set by main, used to check if the program needs to show informational popups
    scan_stopped = False  # to know if the network scan is running
    running_stopped = False  # to know if the program is running (or if the view has been closed)
    auto_select = False  # auto_select of the first available wireless interface (option -a in the console)
    cracking_completed = False  # to know if the network cracking process has finished or not
    cracking_network = False  # state of the network cracking process (if it has started or not)
    net_attack = ""  # EncryptionType generic object, used to store the specific instance of the running attack
    verbose_level = 0  # level 1: minimal output, level 2: advanced output, level 3: advanced output and commands
    allows_monitor = True  # to know if the wireless interface allows monitor mode
    spoof_mac = False  # spoof a client's MAC address
    silent_attack = False  # if the network attack should be run in silent mode
    ignore_local_savefiles = False  # option to ignore the local files, for both creating and reading them
    scan_filter_parameters = ["ALL", "ALL"]  # filter parameters to apply during the scan, [encryption, channel]
    main_directory = ""  # directory where the program is running
    selected_wordlist = "/rockyou.txt"  # default project wordlist
    write_directory = "/tmp/WiCC"  # directory to store all generated dump files, can be modified by the user
    local_folder = "/savefiles"  # folder to locally save files
    path_directory_crunch = ""  # directory to save generated lists with crunch
    generated_wordlist_name = "wicc_wordlist"  # name of the generated files in generate_wordlist()
    hex_values = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f']  # all hex values
    hex_values_even = ['2', '4', '6', '8', 'a', 'c', 'e']  # even hex values
    required_software = [["ifconfig", False], ["aircrack-ng", False], ["pyrit", False], ["cowpatty", False],
                         ["pgrep", False], ["NetworkManager", False], ["genpmk", False], ["iw", False],
                         ['crunch', False]]  # software required to run the program
    mandatory_software = ['ifconfig', 'aircrack-ng']  # mandatory software (from the required one)

    __instance = None  # used for singleton check
    timestamp = 0  # timestamp added to the created dump files (just for the initial scan)
    passwords_file_name = "cracked_networks"  # file to store cracked networks information

    # Semaphores

    semSelectInterface = threading.Semaphore()  # semahpore for the initial state, select an interface
    semStartScan = threading.Semaphore()  # semaphore to notice to start the scan
    semRunningScan = threading.Semaphore()  # semaphore for the running scan state
    semStoppedScan = threading.Semaphore()  # semaphore for when the scan has stopped

    def __init__(self):
        """
        Control class constuctor. Includes a singleton check.
        Sets the object references, and sets the main directory with pwd
        The selected interface semaphore is initialized as released, the others as acquired
        """
        if not Control.__instance:
            self.model = ""
            self.model = Model()
            self.view = View(self)
            self.popup = PopUpWindow()
            directory, err = self.execute_command(['pwd'])
            self.main_directory = directory.decode('utf-8')[:-1]
            self.local_folder = self.main_directory + self.local_folder
            self.selected_wordlist = self.local_folder + self.selected_wordlist
            self.__instance = self

            self.semStartScan.acquire(False)
            self.semRunningScan.acquire(False)
            self.semStoppedScan.acquire(False)
        else:
            raise Exception("Singleton Class")

    def start_view(self):
        """
        Start the view window
        :return:

        :Author: Miguel Yanes Fernández
        """
        self.view.build_window()

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
        """
        Prints a message, if the verbose level is higher or equal to 2
        :param message: message to print
        :return: None

        :Author: Miguel Yanes Fernández
        """
        if self.verbose_level >= 2:
            print(message)

    def set_verbose_level(self, level):
        """
        Sets the class variable for the verbose level
        :param level: verbose level to set
        :return: None

        :Author: Miguel Yanes Fernández
        """
        self.verbose_level = level

    def set_ignore_savefiles(self, ignore_savefiles):
        """
        Set the variable to ignore the local savefiles
        :param ignore_savefiles: value of the variable
        :return: None

        :Author: Miguel Yanes Fernández
        """
        self.ignore_local_savefiles = ignore_savefiles

    def set_informational_popups(self, info_popups):
        """
        Set the variable for the informational popups
        :param info_popups: variable value
        :return: None

        :Author: Miguel Yanes Fernández
        """
        self.informational_popups = info_popups

    def set_auto_select(self, auto_select):
        """
        Sets the value for the auto select option
        :param auto_select: variable value
        :return: None

        :Author: Miguel Yanes Fernández
        """
        self.auto_select = auto_select

    def set_semaphores_state(self, state):
        """
        Method to set the semaphores value depending on the execution state (4 different states)
        :param state: execution state
        :return: None

        :Author: Miguel Yanes Fernández
        """
        if state == "Select interface":
            self.semSelectInterface.release()
            self.semStartScan.acquire(False)
            self.semRunningScan.acquire(False)
            self.semStoppedScan.acquire(False)
        elif state == "Start scan":
            self.semSelectInterface.acquire(False)
            self.semStartScan.release()
            self.semRunningScan.acquire(False)
            self.semStoppedScan.acquire(False)
        elif state == "Running scan":
            self.semSelectInterface.acquire(False)
            self.semStartScan.acquire(False)
            self.semRunningScan.release()
            self.semStoppedScan.acquire(False)
        elif state == "Stop scan":
            self.semSelectInterface.acquire(False)
            self.semStartScan.acquire(False)
            self.semRunningScan.acquire(False)
            self.semStoppedScan.release()

    def check_software(self):
        """
        Check whether the required software is installed or not.
        :return: list of software (array of booleans), a boolean to say if any is missing, and a boolean to know if its
                 necessary to stop the execution (missing mandatory software)
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

            self.show_info_notification(info_msg)

        return self.required_software, some_missing, stop_execution

    def check_monitor_mode(self):
        """
        Checks if the selected interface supports monitor mode
        (done with iw list, works better if only one interface is connected)
        :return: whether the selected interface supports monitor mode

        :Author: Miguel Yanes Fernández
        """
        iw_cmd = ['iw', 'list']
        iw_out, iw_err = self.execute_command(iw_cmd)

        iw_out = iw_out.decode('utf-8')
        lines = iw_out.split('\n')
        for line in lines:
            words = line.split(' ')
            if "monitor" in words:
                self.allows_monitor = True
                return

    def scan_interfaces(self):
        """
        Scans all network interfaces. After filtering them (method filter_interfaces),
        scans available wireless interfaces. Finally calls the method filter_w_interface
        :return: none

        :Author: Miguel Yanes Fernández
        """
        # ifconfig
        if_output, if_error = self.execute_command(['ifconfig'])
        if_output = if_output.decode("utf-8")
        if_error = if_error.decode("utf-8")

        if if_error is not None:
            w_interfaces = self.filter_interfaces(if_output)
        else:
            return

        self.model.clear_interfaces()

        # iw info
        interfaces = []
        for w_interface in w_interfaces:

            # command example: iw wlan0 info
            iw_output, iw_error = self.execute_command(['iwconfig', w_interface])
            iw_output = iw_output.decode("utf-8")
            iw_error = iw_error.decode("utf-8")
            iw_error = iw_error.split(':')
            # if there is no error, it is a wireless interface
            if iw_output:
                interfaces.append(self.filter_w_interface(iw_output))
                if self.auto_select:
                    self.selected_interface = self.filter_w_interface(iw_output)[0]
                    self.last_selectedInterface = self.selected_interface
                    self.set_semaphores_state("Start scan")
                    self.view.set_buttons(False)
                elif self.last_selectedInterface != "":
                    self.selected_interface = self.last_selectedInterface
        self.set_interfaces(interfaces)

    @staticmethod
    def filter_interfaces(str_ifconfig):
        """
        Filters the input for all network interfaces
        :param str_ifconfig: string taken from the command execution stdout
        :return: array of names of all network interfaces

        :Author: Miguel Yanes Fernández
        """
        interfaces = str_ifconfig.split('\n')
        names_interfaces = []

        for line in interfaces:
            if line[:1] != " " and line[:1] != "":
                info = line.split(" ")
                info = info[0].split(":")

                name = info[0]
                names_interfaces.append(name)
        return names_interfaces

    def filter_w_interface(self, str_iw_info):
        """
        Filters the input for a single wireless interface. First checks if the interface is wireless
        :param str_iw_info: stdout for the command to see the wireless interfaces
        :return: array with the Interface parameters

        :Author: Miguel Yanes Fernández
        """
        # Interface: name address type power channel
        interface = ["", "", "", 0, 0]
        str_iw_info = str_iw_info.split("\n")
        for lines in str_iw_info:
            # if last line
            if lines == "":
                break

            # reads the data from each line
            line = lines.split()
            if interface[0] == "":
                interface[0] = line[0]
            if "Mode" in lines:
                for i in range(0, len(line)):
                    if "Mode" in line[i]:
                        str = line[i].split(":")
                        interface[2] = str[1]
                        break
        interface[1] = self.mac_checker(interface[0])
        return interface

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
        command to a file with a timestamp
        This file is then passed to the method filter_networks
        :return: none

        :Author: Miguel Yanes Fernández & Pablo Sanz Alguacil
        """
        self.model.clear_networks()
        self.notify_view()

        if not self.model.get_mac(self.selected_interface):
            self.selected_interface = self.selected_interface[:-3]
            self.stop_scan()
            self.selected_interface = ""
            if not self.auto_select:
                self.show_info_notification("Card already in monitor mode.\nPlease, re-select the wireless interface")
                self.show_message("Card already in monitor mode")
                self.view.set_buttons(True)
                self.set_semaphores_state("Select interface")
            self.model.clear_interfaces()
            return False

        scan_info_thread = threading.Thread(target=self.show_info_notification,
                                            args=(" - Scanning networks -\nStop the scan to select a network",))
        scan_info_thread.start()

        self.check_monitor_mode()

        if not self.allows_monitor:
            self.show_info_notification("The selected interface doesn't support monitor mode")
            self.set_semaphores_state("Select interface")
            return False

        self.scan_stopped = False

        tempfile = self.write_directory + "/net_scan_"

        self.execute_command(['mkdir', self.write_directory])

        airmon_cmd = ['airmon-ng', 'start', self.selected_interface]
        interface = self.selected_interface + 'mon'
        self.execute_command(airmon_cmd)

        self.timestamp = int(datetime.datetime.now().timestamp() * 1000000)  # multiplied to get the full timestamp
        tempfile += str(self.timestamp)

        command = ['airodump-ng', interface, '--write', tempfile, '--output-format', 'csv']

        if self.scan_filter_parameters[0] != "ALL":
            command.append('--encrypt')
            command.append(self.scan_filter_parameters[0])
        if self.scan_filter_parameters[1] != "ALL":
            command.append('--channel')
            command.append(self.scan_filter_parameters[1])

        thread = threading.Thread(target=self.execute_command, args=(command,))
        thread.start()

        return True

    def filter_networks(self):
        """
        Filters the input from the csv file (opens the file and reads it)
        Checks for a exception when reading the file. If there is an exception, tries to fix the problem and
        notifies the user with a warning popup
        :return: none

        :Author: Miguel Yanes Fernández
        """
        tempfile = self.write_directory + "/net_scan_"
        tempfile += str(self.timestamp)
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
        except:
            try:
                # check if the problem was because the interface was already in monitor mode, and try to fix it
                if self.selected_interface[-3:] == 'mon':
                    self.selected_interface = self.selected_interface[:-3]
                    self.show_message("Interface was already in monitor mode, resetting to: " + self.selected_interface)
                    self.stop_scan()
                    self.scan_networks()
                    return True
                self.show_message(" * Error * - Wireless card may not support monitor mode")
                self.show_info_notification("Error when scanning networks. \n"
                                            "The selected wireless card may not support Monitor mode")
                self.selected_interface = ""
                self.stop_scan()
                self.view.set_buttons(True)
                self.set_semaphores_state("Select interface")
                return False
            except Exception:
                # Unknown exception. Tries to fix it by resetting the interface, but may not work
                out, err = self.execute_command(['airmon-ng', 'stop', self.selected_interface])
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
                                     "your wireless card"
                    self.show_message(Exception.args)
                self.show_warning_notification(exception_msg)
                self.view.set_buttons(True)
                return False

    def set_networks(self, networks):
        """
        Using the model instance, sets the new scanned networks (all of them, overwriting the old ones)
        :param networks: list of instances of objects from the class Network
        :return: none

        :Author: Miguel Yanes Fernández
        """
        self.model.set_networks(networks)

    def set_clients(self, clients):
        """
        Given a list of clients, tells the model to store them
        :param clients: list of parameters of clients
        :return: none

        :Author: Miguel Yanes Fernández
        """
        self.model.set_clients(clients)

    def has_selected_interface(self):
        """
        Method to check if there is a selected wireless interface
        :return: true or false whether the selected interface exists or is null

        :Author: Miguel Yanes Fernández
        """
        return self.selected_interface != ""

    def has_selected_network(self):
        """
        Method to check if there is a selected network to attack
        :return: true or false whether the selected network exists or is null

        :Author: Miguel Yanes Fernández
        """
        return self.selected_network != ""

    def add_net_attack(self, mac, object_reference):
        """
        Add a net_attack object (EncryptionType object, whether a WPA or WEP child). Includes the mac so that it can
        be searched if needed
        :param mac: network mac
        :param object_reference: net_attack object reference (EncType object type)
        :return: none
        """
        self.model.add_net_attack(mac, object_reference)

    def get_net_attack(self, mac):
        """
        Gets a net_attack object with a given mac
        :param mac: network mac to search
        :return: net_attack object reference
        """
        return self.model.get_net_attack(mac)

    def notify_view(self):
        """
        Send notify to update the view with the list of interfaces and networks
        :return:

        :Author: Miguel Yanes Fernández
        """
        if not self.get_running_stopped():
            interfaces, networks = self.model.get_parameters()
            try:
                self.view.get_notify(interfaces, networks)
            except:
                try:
                    # sometimes works the second time because the resource was busy
                    time.sleep(1)
                    self.show_message("Error communicating control with view, retrying...")
                    self.view.get_notify(interfaces, networks)
                    self.show_message("Success")
                except:
                    self.show_message("\t* Error while notifying view (try restarting the program)")
                    self.show_error_notification("Fatal error", "Error communicating with the view.\n"
                                                                "Try restarting the program")
                    self.get_notify(Operation.STOP_RUNNING, None)

    def get_notify(self, operation, value):
        """
        Receives the notify generated by the view
        :param operation: type of operation (from the enumeration class Operation)
        :param value: value applied to that operation
        :return: none

        :Author: Miguel Yanes Fernández & Pablo Sanz Alguacil
        """
        if operation == Operation.SELECT_INTERFACE:
            self.selected_interface = value
            if self.selected_interface == "":
                self.view.set_buttons(True)
                self.show_info_notification("Please, select a network interface")
            else:
                self.set_semaphores_state("Start scan")
        elif operation == Operation.SELECT_NETWORK:
            self.selected_network = value
            self.set_buttons_wpa_initial()
            self.set_buttons_wep_initial()
            self.set_semaphores_state("Stop scan")
        elif operation == Operation.ATTACK_NETWORK:
            self.stop_scan()
            self.attack_network()
        elif operation == Operation.STOP_SCAN:
            self.stop_scan()
            self.semRunningScan.acquire(False)
            self.semStoppedScan.release()
        elif operation == Operation.STOP_RUNNING:
            self.stop_running()
        elif operation == Operation.SCAN_OPTIONS:
            self.apply_filters(value)
        elif operation == Operation.CUSTOMIZE_MAC:
            self.customize_mac(value)
        elif operation == Operation.RANDOMIZE_MAC:
            self.randomize_mac(value)
        elif operation == Operation.RESTORE_MAC:
            self.restore_mac(value)
        elif operation == Operation.SPOOF_MAC:
            self.spoof_mac = value
        elif operation == Operation.CHECK_MAC:
            self.mac_checker(value)
        elif operation == Operation.SELECT_CUSTOM_WORDLIST:
            self.selected_wordlist = value
        elif operation == Operation.PATH_GENERATED_LISTS:
            self.path_directory_crunch = value
        elif operation == Operation.GENERATE_LIST:
            self.generate_wordlist(value)
        elif operation == Operation.SELECT_TEMPORARY_FILES_LOCATION:
            self.write_directory = value
        elif operation == Operation.START_SCAN_WPA:
            self.scan_wpa()
        elif operation == Operation.SILENT_SCAN:
            self.silent_attack = value
        elif operation == Operation.OPEN_CRACKED:
            self.open_cracked_passwords()

    def stop_running(self):
        """
        Stops the program execution. Notifies the view to finish itself, then deletes the reference.
        :return: none

        :Author: Miguel Yanes Fernández
        """
        try:
            self.stop_scan()
            self.view.reaper_calls()
            self.show_message("\n\n\tClossing WiCC ...\n\n")
            os.close(2)  # block writing to stderr
            del self.view
            self.running_stopped = True
            exit(0)
        except:
            raise SystemExit

    def stop_scan(self):
        """
        Series of commands to be executed to stop the scan. Kills the process(es) related with airodump, and then
        resets the wireless interface.
        :return: none

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
        airmon_cmd = ['airmon-ng', 'stop', self.selected_interface + 'mon']  # stop card to be in monitor mode
        ifconf_up_cmd = ['ifconfig', self.selected_interface, 'up']  # sets the wireless interface up again
        net_man_cmd = ['NetworkManager']  # restarts NetworkManager

        self.execute_command(airmon_cmd)
        self.execute_command(ifconf_up_cmd)
        self.execute_command(net_man_cmd)

        self.scan_stopped = True

        try:
            out, err = self.execute_command(['rm', self.write_directory + '/net_scan_' + self.timestamp + '-01.csv'])
        except:
            pass

    def get_interfaces(self):
        """
        Return the list of interfaces from Model
        :return: list of interfaces

        :Author: Miguel Yanes Fernández
        """
        return self.model.get_interfaces()

    def show_info_notification(self, message):
        """
        Creates an info popup
        :param message: message for the popup
        :return: none

        :Author: Miguel Yanes Fernández
        """
        if self.informational_popups:
            self.popup.info("", message)

    def show_warning_notification(self, message):
        """
        Creates a warning popup
        :param message: message for the warning popup
        :return: none

        :Author: Miguel Yanes Fernández
        """
        self.popup.warning("Warning", message)

    def show_error_notification(self, title, message):
        """
        Creates an error popup
        :param title: title of the popup
        :param message: error message
        :return: none

        :Author: Miguel Yanes Fernández
        """
        self.popup.error(title, message)

    def show_yesno_notification(self, title, question):
        """
        Creates a yesno question popup
        :param title: title of the popup
        :param question: question message
        :return: selected answer (boolean)

        :Author: Miguel Yanes Fernández
        """
        return self.popup.yesno(title, question)
    
    def show_okcancel_notification(self, title, question):
        """
        Creates an okcancel popup
        :param title: title of the popup
        :param question: message
        :return: answer (boolean)

        :Author: Miguel Yanes Fernández
        """
        return self.popup.okcancel(title, question)

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

    def set_buttons_wpa_initial(self):
        """
        Sets buttons state for the initial wpa scan/attack
        :return: none

        :Author: Miguel Yanes Fernández
        """
        self.view.get_notify_buttons(["scan_wpa"], True)
        self.view.get_notify_buttons(["stop_scan_wpa", "attack_wpa", "stop_attack_wpa",
                                      "attack_wep", "stop_attack_wep"], False)

    def set_buttons_wpa_scanning(self):
        """
        Set buttons state for the scaning mode in wpa
        :return: none

        :Author: Miguel Yanes Fernández
        """
        self.view.get_notify_buttons(["stop_scan_wpa"], True)
        self.view.get_notify_buttons(["scan_wpa", "attack_wpa", "stop_attack_wpa"], False)

    def set_buttons_wpa_scanned(self):
        """
        Sets buttons state for the scanned mode
        """
        self.view.get_notify_buttons(["scan_wpa", "attack_wpa"], True)
        self.view.get_notify_buttons(["stop_scan_wpa", "stop_attack_wpa"], False)

    def set_buttons_wpa_attacking(self):
        self.view.get_notify_buttons(["stop_attack_wpa"], True)
        self.view.get_notify_buttons(["scan_wpa", "stop_scan_wpa", "attack_wpa"], False)

    def set_buttons_wep_initial(self):
        self.view.get_notify_buttons(["attack_wep"], True)
        self.view.get_notify_buttons(["stop_attack_wep"], False)

    def set_buttons_wep_attacking(self):
        self.view.get_notify_buttons(["attack_wep"], False)
        self.view.get_notify_buttons(["stop_attack_wep"], True)

    def scan_wpa(self):
        """
        Scan a wpa network, waiting until a handshake is captured
        :return: none

        :Author: Miguel Yanes Fernández
        """
        self.set_buttons_wpa_scanning()

        network = self.model.search_network(self.selected_network)

        self.show_message("create wpa instance")

        self.net_attack = self.get_net_attack(network.get_bssid())
        if not self.net_attack:
            self.net_attack = WPA(network, self.selected_interface, self.selected_wordlist,
                                  self.verbose_level, self.silent_attack, self.write_directory)

        self.add_net_attack(network.get_bssid(), self.net_attack)

        choice = self.show_yesno_notification("Starting WPA scan",
                                              "You are about to start the scanning process on the "
                                              "WPA network:\n\n - " + network.get_essid() +
                                              "\n\nThe process will take up to a few minutes."
                                              "\n¿Do you want to start the scan?")
        if not choice:
            self.set_buttons_wpa_initial()
            return

        self.show_message("start scanning")
        self.net_attack.scan_network()
        if not self.net_attack.get_injection_supported() and not self.silent_attack:
            self.show_info_notification("The selected interface doesnt support packet injection."
                                        "\nAutomatically switching to silent mode (no client de-authing)"
                                        "\n\nThe attack will be slower")
        self.show_message("Scanned network - Handshake captured")

        self.show_info_notification("Handshake captured.\n\nYou can now start the attack (cracking process)")
        self.set_buttons_wpa_scanned()
        self.set_semaphores_state("Stop scan")
        return

    def attack_network(self):
        """
        Method to start the attack depending on the type of selected network.
        :return: none

        :Author: Miguel Yanes Fernández
        """
        self.set_buttons_wep_attacking()
        self.set_buttons_wpa_attacking()

        password = self.check_cracked_networks(self.passwords_file_name)
        if password != "":
            self.show_info_notification("Network already cracked\n\nPassword: " + password +
                                             "\n\nYou can now restart the scanning process")
            self.cracking_completed = True
            self.stop_scan()
            self.selected_network = ""
            self.set_buttons_wep_initial()
            self.set_buttons_wpa_initial()
            return

        network = self.model.search_network(self.selected_network)
        password = ""
        # try:
        network_encryption = network.get_encryption()
        time.sleep(0.01)

        # ------------- OPEN network ----------------
        if network_encryption == " OPN":
            self.show_info_notification("The selected network is open. No password required to connect")
            self.cracking_completed = True
            self.stop_scan()
            self.selected_network = ""
            self.set_buttons_wep_initial()
            self.set_buttons_wpa_initial()
            return

        choice = self.show_yesno_notification("Starting cracking process",
                                              "You are about to start the cracking process on the "
                                              " network:\n - " + network.get_essid() +
                                              "\n\nThe process will take up to a few minutes."
                                              "\n¿Do you want to start the cracking process?")
        if not choice:
            self.set_buttons_wep_initial()
            return

        # ------------- WEP Attack ----------------
        if network_encryption == " WEP":
            if self.spoof_mac:
                attacker_mac = self.spoof_client_mac(self.selected_network)
                self.show_message("Spoofed client MAC: " + attacker_mac)
            else:
                attacker_mac = self.mac_checker(self.selected_interface, )
                self.show_message("Attacker's MAC: " + attacker_mac)

            self.show_message("WEP attack")
            self.net_attack = WEP(network, self.selected_interface, attacker_mac,
                                  self.verbose_level, self.silent_attack, self.write_directory)

            self.show_message("Scanning network")
            password = self.net_attack.scan_network()
            self.show_message("Cracking finished")

        # ------------- WPA Attack ----------------
        elif network_encryption[:4] == " WPA":
            if self.selected_wordlist == "":
                self.show_info_notification("You need to select a wordlist for the WPA attack")
                self.set_buttons_wpa_scanned()
                return
            self.show_message("create wpa instance")
            self.net_attack = self.get_net_attack(network.get_bssid())
            self.net_attack.add_wordlist(self.selected_wordlist)
            self.show_message("start cracking")
            self.cracking_network = True

            password = self.net_attack.crack_network()
            self.show_message("finished cracking")
            self.cracking_network = False
            # pass

        # ------------- Unsupported encryption -----------
        else:
            self.show_info_notification("Unsupported encryption type. Try selecting a WEP or WPA/WPA2 network")

        self.cracking_completed = True
        self.stop_scan()

        if password != "":
            self.show_info_notification("Cracking process finished\n\nPassword: " + password +
                                             "\n\nYou can now restart the scanning process")
            self.create_local_folder()
            bssid = self.model.search_network(self.selected_network).get_bssid()
            essid = self.model.search_network(self.selected_network).get_essid()
            self.store_local_file(self.passwords_file_name, bssid + " " + password + " " + essid)
        else:
            self.show_info_notification("Cracking process finished\n\nNo password retrieved"
                                             "\n\nYou can restart the scanning process")

        self.set_buttons_wep_initial()
        self.set_buttons_wpa_initial()

    def create_local_folder(self):
        """
        Create (if doesn't exist) a local folder to store program-related files
        :return: none

        :Author: Miguel Yanes Fernández
        """

        if not self.ignore_local_savefiles:
            mkdir_cmd = ['mkdir', self.local_folder]
            self.execute_command(mkdir_cmd)

    def store_local_file(self, file_name, file_contents):
        """
        Stores the passed content in a local file (adds the content if it already exists)
        :param file_name: name of the file
        :param file_contents: contents to store on the file
        :return: none

        :Author: Miguel Yanes Fernández
        """
        if not self.ignore_local_savefiles:
            with open(self.local_folder + "/" + file_name, "a") as file:
                file.write(file_contents + "\n")
                file.close()
            chmod_cmd = ['chmod', '664', self.local_folder + "/" + file_name]
            self.execute_command(chmod_cmd)

    def read_local_file(self, file_name):
        """
        Read contents of a local file
        :param file_name: name of the file to read
        :return: file contents

        :Author: Miguel Yanes Fernández
        """
        if not self.ignore_local_savefiles:
            try:
                with open(self.local_folder + "/" + file_name, "r") as file:
                    return file.read()
            except:
                self.show_message("There are no stored cracked networks")

    def check_cracked_networks(self, file_name):
        """
        Check if a network has been cracked, using the created file
        :param file_name: file name to check
        :return: password, if any is found

        :Author: Miguel Yanes Fernández
        """
        contents = self.read_local_file(file_name)
        if contents:
            lines = contents.split("\n")
            for line in lines:
                words = line.split()
                if line != "":
                    if words[0] == self.model.search_network(self.selected_network).get_bssid():
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
        """
        Method to know if control is cracking a network
        :return: cracking state

        :Author: Miguel Yanes Fernández
        """
        return self.cracking_network

    def spoof_client_mac(self, id):
        """
        Method to spoof a network client's MAc
        :param id: network id to select a client mac
        :return: spoofed client mac

        :Author: Miguel Yanes Fernández
        """
        network = self.model.search_network(id)
        if network.get_clients() != 0:
            client = network.get_first_client()
            client_mac = client.get_mac()
            return client_mac
        else:
            return self.model.get_mac(self.selected_interface)

    def randomize_mac(self, interface):
        """
        Generates a random MAC address.
        Calls customize_mac() to set the generated address
        :param interface: string. The name of the interface to use
        :return:

        :author: Pablo Sanz Alguacil
        """
        generated_address = ""

        first_digit = self.hex_values[random.randint(0, 15)]
        second_digit = self.hex_values_even[random.randint(0, 6)]
        generated_address += first_digit + second_digit + ":"
        for i in range(0, 4):
            first_digit = self.hex_values[random.randint(0, 15)]
            second_digit = self.hex_values[random.randint(0, 15)]
            generated_address += first_digit + second_digit + ":"
        else:
            first_digit = self.hex_values[random.randint(0, 15)]
            second_digit = self.hex_values[random.randint(0, 15)]
            generated_address += first_digit + second_digit

        self.customize_mac((interface, generated_address))

    def customize_mac(self, values):
        """
        Generates and executes the command to set a custom MAC address.
        :param values: 0 - interface, 1 - mac address
        :return:

        :author: Pablo Sanz Alguacil
        """
        try:
            command1 = ['ifconfig', values[0], 'down']
            command2 = ['ifconfig', values[0], 'hw', 'ether', values[1]]
            command3 = ['ifconfig', values[0], 'up']
            self.execute_command(command1)
            self.execute_command(command2)
            self.execute_command(command3)
        except:
            self.show_warning_notification("Unable to set new MAC address")

        if self.mac_checker(values[0]) != values[1]:
            self.customize_mac(values)

    def restore_mac(self, interface):
        """
        Generates and executes the command to restore the original MAC address.
        :param interface: string cointainig the name of the target interface

        :author: Pablo Sanz Alguacil
        """
        try:
            command1 = ['ifconfig', interface, 'down']  # Turns down the interface
            self.execute_command(command1)
            command2 = ['ethtool', '-P', interface]  # Gets permanent(original) MAC address
            original_mac = self.execute_command(command2)[0].decode("utf-8").split(" ")[-1]
            command3 = ['ifconfig', interface, 'hw', 'ether', original_mac]  # Sets the original MAC as current MAC
            self.execute_command(command3)
            command4 = ['ifconfig', interface, 'up']  # Turns on the interface
            self.execute_command(command4)
        except:
            self.show_warning_notification("Unable to restore original MAC address")

    def mac_checker(self, interface):
        """
        Generates and executes the command to get the curretn MAC address.
        :param interface: string cointainig the name of the target interface
        :return: string containing the current MAC address, Flase in case of error

        :author: Pablo Sanz Alguacil and Miguel Yanes Fernández
        """
        try:
            command = ['ifconfig', interface]
            current_mac = self.execute_command(command)[0].decode("utf-8").split(" ")
            for i in range(0, len(current_mac)):
                if current_mac[i] == "ether":
                    current_mac = current_mac[i + 1]
                    return current_mac
            return None
        except:
            self.show_warning_notification("Unable to get current MAC address")
            return False

    def get_running_stopped(self):
        """
        Gets the running state of the program
        :return: running state

        :Author: Miguel Yanes Fernández
        """
        return self.running_stopped

    def generate_wordlist(self, words_list):
        """
        Generates and executes the command to generate a custom wordlist using crunch.
        :param words_list: array containing the words to generate the list.

        :author: Pablo Sanz Alguacil
        """
        index = 0
        exists = True
        file_name = ""

        if self.path_directory_crunch != "":
            directory = self.path_directory_crunch
        else:
            directory = self.local_folder

        while exists:
            if index == 0:
                file_name = self.generated_wordlist_name + ".txt"
            else:
                file_name = self.generated_wordlist_name + "(" + str(index) + ").txt"

            file_path = directory + "/" + file_name
            exists = os.path.isfile(file_path)
            index += 1

        output_list = directory + "/" + file_name
        command = ['crunch', '0', '0', '-o', output_list, '-p']
        for word in words_list:
            command.append(word)

        self.show_message("Generating custom wordlist")
        self.execute_command(command)

    def get_wordlist(self):
        """
        Get the selected wordlist (or the project wordlist if any is selected)
        :return: wordlist directory

        :Author: Miguel Yanes Fernández
        """
        return self.selected_wordlist

    def set_wordlist(self, wordlist):
        """
        Set the project wordlist
        :param wordlist: selected wordlist directory
        :return: none

        :Author: Miguel Yanes Fernández
        """
        self.selected_wordlist = wordlist

    def open_cracked_passwords(self):
        """
        Opens the cracked passwords file.

        :author: Pablo Sanz Alguacil
        """

        try:
            self.show_message("Opening passwords file")
            passwords = self.local_folder + "/" + self.passwords_file_name
            open(passwords, 'r').close()  # just to raise an exception if the file doesn't exists
            command = ['xdg-open', passwords]
            thread = threading.Thread(target=self.execute_command, args=(command,))
            thread.start()
        except FileNotFoundError:
            self.show_warning_notification("No stored cracked networks. You need to do and finish an attack")
