#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from wicc_control import Control
import sys
import os
import time
import threading


verbose_level = 0


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

    control = Control()

    exit = False

    print("\n\tStarting WiCC\n")

    headless = False  # run the program without the front-end
    auto_select = False  # auto-select the network interface
    args = sys.argv[1:]
    for arg in args:
        if '-v' in arg:
            if verbose_level == 0:
                if arg == '-v':
                    control.set_verbose_level(1)
                    verbose_level = 1
                    print(" *** Verbose level set to " + str(verbose_level) + "\n")
                elif arg == '-vv':
                    control.set_verbose_level(2)
                    verbose_level = 2
                    print( "*** Verbose level set to " + str(verbose_level) + "\n")
                elif arg == '-vvv':
                    control.set_verbose_level(3)
                    verbose_level = 3
                    print(" *** Verbose level set to " + str(verbose_level) + "\n")
        elif arg == '-h':
            if not headless:
                headless = True
                print(" *** Running program headless\n")
        elif arg == '-a':
            if not auto_select:
                auto_select = True
                print(" *** Auto-select network interface\n")
        elif arg == '--help':
            print(" ***  -h to run the program headless")
            print(" ***  -a to auto-select the first available network interface")
            print(" ***  -v to select the verbose level for the program")
            print("\t-v   for level 1 (basic output)")
            print("\t-vv  for level 2 (advanced output)")
            print("\t-vvv for level 3 (advanced output and executed commands)\n")
            sys.exit(0)
        else:
            print("*** Unrecognized option " + arg)
            print("*** Use option --help to view the help and finish execution. Only for debugging purposes\n")
            break

    software, some_missing = control.check_software()
    if some_missing:
        # variable 'software' is an array of pair [tool_name, boolean_if_its_installed]
        print("The required software is not installed:\n")
        for i in range(0, len(software)):
            if not software[i][1]:
                print("\t***Missing " + software[i][0])
        print("\n")
        sys.exit(1)
    else:
        show_message("All required software is installed")

    if headless:
        view_thread = threading.Thread(target=control.start_view, args=(True,))
    else:
        view_thread = threading.Thread(target=control.start_view, args=(False,))
    view_thread.start()
    view_thread.join(1)
    while not exit:
        if control.has_selected_interface():
            show_message("Selected interface: " + control.selectedInterface)
            control.scan_networks()
            show_message("Start scanning available networks...")
            time.sleep(3)
            while not control.selectedNetwork and control.running_scan():
                time.sleep(1)
                show_message("\t... Scanning networks ...")
                if not control.filter_networks():
                    time.sleep(1)
                    control.stop_scan()
                    time.sleep(1)
                    show_message(" * An error ocurred, please, re-select the interface")
                    control.selectedInterface = ""
                    control.last_selectedInterface = ""
                    control.model.interfaces = []
                    while not control.has_selected_interface():
                        control.scan_interfaces(auto_select)
                        show_message("Scanning interfaces")
                        time.sleep(1)
                    show_message("Selected interface: " + control.selectedInterface)
                    control.scan_networks()
                    show_message("Start scanning available networks...")
                    time.sleep(3)
            show_message("\n * Network scanning stopped * \n")
            while not control.selectedNetwork:
                # waits until a network is selected
                time.sleep(1)
            show_message("Selected network: " + str(control.selectedNetwork))
            show_message("\nStarting attack...\n")

            while not control.cracking_completed and not control.is_cracking_network():
                show_message("\t... Cracking network ...")
                time.sleep(1)

            while control.is_cracking_network():
                show_message("\t... Cracking password ...")
                # print(control.check_cracking_status())
                time.sleep(1)

            show_message("Cracking process finished.")
            sys.exit(0)
        else:
            show_message("Scanning interfaces")
            control.scan_interfaces(auto_select)
            time.sleep(1)
            if control.get_interfaces() == "":
                control.view.show_info_notification("No wireless interfaces found."
                                                    "\n\nPlease connect a wireless card.")

    view_thread.join(0)
