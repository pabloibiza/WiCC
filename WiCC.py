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


def print_ascii(file):
    output = ""
    with open(file, "r") as art:
        for line in art:
            output += line
    print(output)


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

    # print_ascii("Resources/ascii_art.txt")
    print(cyan + "=============================================")
    print(light_blue + "      __      __ ___________  ________   ")
    print("     /  \    /  \__\_   ___ \|_   ___ \  ")
    print("     \   \/\/   /  /    \  \//    \  \/ ")
    print(blue +"      \        /|  \     \___\     \____ ")
    print("       \__/\__/ |__|\________/\________/ ")
    print("")
    print("")
    print("              Wifi Cracking Camp")
    print(cyan + "=============================================")

    control = Control()

    headless = False  # run the program without the front-end
    auto_select = False  # auto-select the network interface
    splash_image = True  # show splash image during startup
    ignore_savefiles = False  # ignore the generated local savefiles
    args = sys.argv[1:]

    options_message = ""
    for arg in args:
        print(light_cyan)
        if '-v' in arg:
            if verbose_level == 0:
                if arg == '-v':
                    control.set_verbose_level(1)
                    verbose_level = 1
                    options_message += " *** Verbose level set to " + str(verbose_level) + "\n"
                elif arg == '-vv':
                    control.set_verbose_level(2)
                    verbose_level = 2
                    options_message += "*** Verbose level set to " + str(verbose_level) + "\n"
                elif arg == '-vvv':
                    control.set_verbose_level(3)
                    verbose_level = 3
                    options_message += " *** Verbose level set to " + str(verbose_level) + "\n"
        elif arg == '-h':
            if not headless:
                headless = True
                options_message += " *** Running program headless\n"
        elif arg == '-a':
            if not auto_select:
                auto_select = True
                options_message += " *** Auto-select network interface\n"
        elif arg == '-s':
            if splash_image:
                splash_image = False
                options_message += " *** Not showing splash image\n"
        elif arg == '-i':
            if not ignore_savefiles:
                ignore_savefiles = True
                control.set_ignore_savefiles(ignore_savefiles)
                options_message += " *** Ignoring local savefiles\n"
        elif arg == '--help':
            print("Viewing help")
            print("Usage: # python3 WiCC.py [option(s)]\n")
            print("Options (mainly for debugging purposes):")
            print("   -h | --help \tshow the help")
            print("   -a \t\tauto-select the first available network interface")
            print("   -s \t\tavoid showing the splash image during startup")
            print("   -i \t\tignore local save files")
            print("   -v \t\tselect the verbose level for the program (default: 0, no output)")
            print("\t-v  \tlevel 1 (basic output)")
            print("\t-vv \tlevel 2 (advanced output)")
            print("\t-vvv\tlevel 3 (advanced output and executed commands)\n")
            sys.exit(0)
        else:
            print("*** Unrecognized option " + arg)
            print("*** Use option --help to view the help and finish execution. Only for debugging purposes\n")
            break
    print(options_message)
    print(white)

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

    if headless:
        view_thread = threading.Thread(target=control.start_view, args=(True, splash_image,))
    else:
        view_thread = threading.Thread(target=control.start_view, args=(False, splash_image,))
    view_thread.start()
    view_thread.join(1)

    # control.show_info_notification("Welcome to WiCC\n\nSelect an interface to begin the process")

    while not exit:
        if control.semSelectInterface.acquire(False):
            control.scan_interfaces(auto_select)
            show_message("Scanning interfaces")
            control.semSelectInterface.release()
        elif control.semStartScan.acquire(True):
            show_message("Scanning networks")
            control.scan_networks()
            while control.semRunningScan.acquire(False):
                control.semRunningScan.release()
                show_message(" ... Filtering networks ...")
                control.filter_networks()
                time.sleep(1)
            print("end while")
            control.semStartScan.acquire(False)
            while control.semStoppedScan.acquire(False):
                control.semStoppedScan.release()
                show_message("Scan stopped")
                while control.semSelectNetwork.acquire(False):
                    control.semSelectNetwork.release()
                    print("sel network")
                    time.sleep(1)
                else:
                    print(1)
                    if control.semStartScan.acquire(False):
                        print(2)
                        control.semSelectNetwork.acquire(False)
                        control.semStoppedScan.acquire(False)
                        control.semStartScan.release()
                        control.semRunningScan.release()
                    else:
                        time.sleep(1)
            else:
                print("wtf")
        time.sleep(1)

    exit(0)

    try:
        while not exit and not control.get_running_stopped():
            if control.has_selected_interface():
                if auto_select:
                    control.view.disable_buttons()
                show_message("Selected interface: " + control.selectedInterface)
                if control.scan_networks():
                    show_message("Start scanning available networks...")
                    time.sleep(3)
                    while not control.selectedNetwork and control.running_scan() and not control.get_running_stopped():
                        time.sleep(1)
                        show_message("\t... Scanning networks ...")
                        if not control.filter_networks() and not control.get_running_stopped():
                            time.sleep(1)
                            control.stop_scan()
                            time.sleep(1)
                            show_message(" * An error ocurred, please, re-select the interface")
                            control.selectedInterface = ""
                            control.last_selectedInterface = ""
                            control.model.interfaces = []
                            while not control.has_selected_interface() and not control.get_running_stopped():
                                control.scan_interfaces(auto_select)
                                show_message("Scanning interfaces")
                                time.sleep(1)
                            show_message("Selected interface: " + control.selectedInterface)
                            control.scan_networks()
                            show_message("Start scanning available networks...")
                            time.sleep(3)
                    show_message("\n * Network scanning stopped * \n")
                    if not control.get_running_stopped():
                        while not control.selectedNetwork and not control.get_running_stopped():
                            # waits until a network is selected
                            time.sleep(1)
                        show_message("Selected network: " + str(control.selectedNetwork))
                        show_message("\nStarting attack...\n")

                        while not control.cracking_completed and not control.is_cracking_network() \
                                and not control.get_running_stopped():
                            show_message("\t... Cracking network ...")
                            time.sleep(1)

                        while control.is_cracking_network() and not control.get_running_stopped():
                            show_message("\t... Cracking password ...")
                            # print(control.check_cracking_status())
                            time.sleep(1)

                        show_message("Cracking process finished.")
                        # sys.exit(0)
                    control.selectedInterface = ""
                else:
                    control.stop_scan()
                    control.selectedInterface = ""

            else:
                show_message("Scanning interfaces")
                control.scan_interfaces(auto_select)
                time.sleep(1)
                if control.get_interfaces() == "":
                    control.view.show_info_notification("No wireless interfaces found."
                                                        "\n\nPlease connect a wireless card.")
        sys.exit(0)
    except:
        sys.exit(1)
    sys.exit(0)
