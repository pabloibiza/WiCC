#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from wicc_control import Control
import sys
import os
import time
import threading


verbose_level = 0

green = "\033[32m"
orange = "\033[33m"
blue = "\033[34m"
white = "\033[0m"
cyan = "\033[36m"
light_blue = "\033[1;34m"
light_cyan = "\033[1;36m"


def show_message(message):
    """
    Method to print a message if the verbose level is higher or equal to 1
    :param message: message to pring
    :return: none

    :Author: Miguel Yanes Fernández
    """
    if verbose_level >= 1:
        print(message)


if __name__ == '__main__':
    """
    Main
    
    :Author: Miguel Yanes Fernández
    """

    # check root privilege
    if os.getuid() != 0:
        print("\n\tError: script must be executed as root\n")
        sys.exit(1)

    # checks python version
    if sys.version_info[0] < 3:
        print("\n\tError: Must be executed with Python 3\n")
        sys.exit(1)

    exit = False
    print(cyan)
    print("=============================================" + light_blue)
    print("      __      __ ___________  ________   ")
    print("     /  \    /  \__\_   ___ \|_   ___ \  ")
    print("     \   \/\/   /  /    \  \//    \  \/  " + blue)
    print("      \        /|  \     \___\     \____ ")
    print("       \__/\__/ |__|\________/\________/ ")
    print("")
    print("")
    print("              Wifi Cracking Camp" + cyan)
    print("=============================================")
    print(blue)
    print("Developed by:")
    print("  - Pablo Sanz Alguacil")
    print("  - Miguel Yanes Fernández")
    print("  - Adam Chankley")
    print("")
    print("Project page: https://github.com/pabloibiza/WiCC")

    auto_select = False  # auto-select the network interface
    ignore_savefiles = False  # ignore the generated local savefiles
    verbose_level = 0
    popups = True
    args = sys.argv[1:]

    options_message = ""
    for arg in args:
        print(light_cyan)
        if '-v' in arg:
            if verbose_level == 0:
                if arg == '-v':
                    verbose_level = 1
                    options_message += " *** Verbose level set to " + str(verbose_level) + "\n"
                elif arg == '-vv':
                    verbose_level = 2
                    options_message += "*** Verbose level set to " + str(verbose_level) + "\n"
                elif arg == '-vvv':
                    verbose_level = 3
                    options_message += " *** Verbose level set to " + str(verbose_level) + "\n"
        elif arg == '-a':
            if not auto_select:
                auto_select = True
                options_message += " *** Auto-select network interface\n"
        elif arg == '-i':
            if not ignore_savefiles:
                ignore_savefiles = True
                options_message += " *** Ignoring local savefiles\n"
        elif arg == '-p':
            if popups:
                popups = False
                options_message += " *** Not showing informational popups\n"
        elif arg == '--help' or arg == '-h':
            print("Viewing help")
            print("Usage: # python3 WiCC.py [option(s)]\n")
            print("Options (mainly for debugging purposes):")
            print("   -h | --help \tshow the help")
            print("   -a \t\tauto-select the first available network interface")
            print("   -i \t\tignore local save files")
            print("   -p \t\tnot show informational popups")
            print("   -v \t\tselect the verbose level for the program (default: 0, no output)")
            print("\t-v  \tlevel 1 (basic output)")
            print("\t-vv \tlevel 2 (advanced output)")
            print("\t-vvv\tlevel 3 (advanced output and executed commands)\n")
            sys.exit(0)
        else:
            print("*** Unrecognized option " + arg)
            print("*** Use option --help to view the help and finish execution. Only for debugging purposes\n")
            sys.exit(0)
    print(options_message)
    print(white)

    control = Control()

    control.set_verbose_level(verbose_level)
    control.set_ignore_savefiles(ignore_savefiles)
    control.set_informational_popups(popups)
    control.set_auto_select(auto_select)

    install_required_cmd = ['echo', 'y', '|', 'apt-get', 'install', 'python3-tk', 'iw', 'net-tools', 'aircrack-ng']
    install_optional_cmd = ['echo', 'y', '|', 'apt-get', 'install', 'pyrit', 'crunch', 'make', 'gcc']

    software, some_missing, stop_execution = control.check_software()

    if some_missing:
        # variable 'software' is an array of pair [tool_name, boolean_if_its_installed]
        print("The following software is not installed:\n")
        for i in range(0, len(software)):
            if not software[i][1]:
                print("\t***Missing " + software[i][0])
        print("\n")
        if stop_execution:
            install_required = input("Would you like to install the required mandatory software? (y): ")
            if install_required == 'y':
                control.execute_command(install_required_cmd)
                install_optional = input("Would you also like to install the optional software? (y): ")
                if install_optional == 'y':
                    control.execute_command(install_optional_cmd)
            else:
                sys.exit(1)
        else:
            install_optional = input("Would you like to install the optional software? (y):")
            if install_optional == 'y':
                control.execute_command(install_optional_cmd)
    else:
        show_message("All required software is installed")

    view_thread = threading.Thread(target=control.start_view)
    view_thread.start()
    view_thread.join(1)

    control.show_info_notification("       Welcome to WiCC\n\nSelect an interface to begin the process")

    show_message("Select an interface")
    while not control.get_running_stopped():
        if control.semSelectInterface.acquire(False):
            control.semSelectInterface.release()
            control.scan_interfaces()
        elif control.semStartScan.acquire(False):
            show_message("Start scan")
            control.scan_networks()
            control.semRunningScan.release()
            show_message("Stop the scan to select a network")
        elif control.semRunningScan.acquire(False):
            control.semRunningScan.release()
            control.filter_networks()
        elif control.semStoppedScan.acquire(False):
            show_message("Scan stopped\nSelect a network or start a new scan")
        time.sleep(1)

    sys.exit(0)
