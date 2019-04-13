#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    WiCC (Wireless Cracking Camp)
    GUI tool for wireless cracking on WEP and WPA/WPA2 networks.
    Project developed by Pablo Sanz Alguacil, Miguel Yanes Fernández and Adan Chalkley,
    as the Group Project for the 3rd year of the Bachelor of Sicence in Computing in Digital Forensics and CyberSecurity
    at TU Dublin - Blanchardstown Campus
"""
import threading
import csv


class Scan:

    def __init__(self, control):
        self.control = control
        self.allows_monitor = False

    def execute_command(self, command):
        return self.control.execute_command(command)

    def scan_interfaces(self, auto_select):
        """
        Scans all network interfaces. After filtering them (method filter_interfaces,
        scans available wireless interfaces. Finally calls the method filter_w_interface
        :param auto_select: whether the interface should be selected automatically
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

        last_selected_interface = ""
        selected_interface = ""
        interfaces = []

        # iw info
        for w_interface in w_interfaces:

            # command example: iw wlan0 info
            iw_output, iw_error = self.execute_command(['iw', w_interface, 'info'])
            iw_output = iw_output.decode("utf-8")
            iw_error = iw_error.decode("utf-8")

            iw_error = iw_error.split(':')
            # if there is no error, it is a wireless interface
            if iw_error[0] != "command failed":
                print("ok")
                interfaces.append(self.filter_w_interface(iw_output))
                print("appended")
                if auto_select:
                    print("auto select")
                    selected_interface = self.filter_w_interface(iw_output)[0]
                    last_selected_interface = selected_interface
                    auto_select = auto_select
                elif last_selected_interface != "":
                    print("no auto select")
                    selected_interface = last_selected_interface
                print("if selected")
        print("returning")
        return interfaces, selected_interface, last_selected_interface

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

    @staticmethod
    def filter_w_interface(str_iw_info):
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
            if line[0] == "Interface":
                interface[0] = line[1]
            elif line[0] == "addr":
                interface[1] = line[1]
            elif line[0] == "type":
                interface[2] = line[1]
            elif line[0] == "txpower":
                interface[3] = line[1]
            elif line[0] == "channel":
                interface[4] = line[1]

        return interface

    def check_monitor_mode(self):
        """
        Checks if the selected interface supports monitor mode
        :return: whether the selected interface supports monitor mode

        :Author: Miguel Yanes Fernández
        """
        iw_cmd = ['iw', 'list']
        iw_out, iw_err = self.execute_command(iw_cmd)

        iw_out = iw_out.decode('utf-8')
        lines = iw_out.split('\n')
        for line in lines:
            words = line.split(' ')
            for word in words:
                if word == 'monitor':
                    self.allows_monitor = True
                    return

    def scan_networks(self, write_directory, scan_filter_parameters, selectedInterface):
        """
        Scan all the networks with airodump-ng. Executes the scan concurrently in a thread. Writes the output of the
        command to the file /tmp/WiCC/net_scan-01.csv
        This file is then passed to the method filter_networks
        :return: none

        :Author: Miguel Yanes Fernández & Pablo Sanz Alguacil
        """

        self.check_monitor_mode()

        scan_stopped = False

        tempfile = write_directory + "/net_scan"

        if write_directory[:5] == "/tmp/":
            self.execute_command(['rm', '-r', write_directory])
        out, err = self.execute_command(['mkdir', write_directory])

        # change wireless interface name to the parameter one

        if self.allows_monitor:
            airmon_cmd = ['airmon-ng', 'start', selectedInterface]
            interface = selectedInterface + 'mon'
            self.execute_command(airmon_cmd)
        else:
            interface = self.selectedInterface

        command = ['airodump-ng', interface, '--write', tempfile, '--output-format', 'csv']

        if scan_filter_parameters[0] != "ALL":
            command.append('--encrypt')
            command.append(scan_filter_parameters[0])
        if scan_filter_parameters[1] != "ALL":
            command.append('--channel')
            command.append(scan_filter_parameters[1])

        thread = threading.Thread(target=self.execute_command, args=(command,))
        thread.start()
        thread.join(1)
        # out, err = self.execute_command(['timeout', '1', 'airodump-ng', 'wlan0'])

        return scan_stopped, self.allows_monitor

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
        except:
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
                airmon_cmd = ['airmon-ng', 'stop',
                              self.selectedInterface + 'mon']  # stop card to be in monitor mode
                ifconf_up_cmd = ['ifconfig', self.selectedInterface, 'up']  # sets the wireless interface up again
                net_man_cmd = ['NetworkManager']  # restarts NetworkManager

                self.execute_command(airmon_cmd)
                self.execute_command(ifconf_up_cmd)
                self.execute_command(net_man_cmd)
        self.scan_stopped = True


