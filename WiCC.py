from wicc_control import Control
import sys
import os
import time
import threading


if __name__ == '__main__':
    # check root privilege
    if os.getuid() != 0:
        print("\n\tError: script must be executed as root\n")
        sys.exit(1)

    # checks python version
    if sys.version_info[0] < 3:
        print("\n\tError: Must be executed with Python 3\n")
        sys.exit(1)

    control = Control()

    software, some_missing = control.check_software()
    if some_missing:
        print("The required software is not installed:\n")
        for i in range(0, len(software)):
            if not software[i]:
                if i == 0:
                    print("\t***Missing ifconfig")
                elif i == 1:
                    print("\t***Missing aircrack-ng")
                elif i == 2:
                    print("\t***Missing pyrit")

        print("\n")
        sys.exit(1)

    exit = False

    print("\n\tStarting WiCC\n")

    headless = False  # run the program without the front-end
    auto_select = False  # auto-select the network interface
    args = sys.argv[1:]
    for arg in args:
        if arg == '-h':
            headless = True
            print("*** Running program headless\n")
        elif arg == '-a':
            auto_select = True
            print("*** Auto-select network interface\n")
        elif arg == '--help':
            print("*** Use option -h to run the program headless")
            print("*** Use option -a to auto-select the first available network interface\n")
        else:
            print("*** Unrecognized option " + arg)
            print("*** Use option --help to view the help. Only for debugging purposes\n")

    if headless:
        view_thread = threading.Thread(target=control.start_view, args=(True,))
    else:
        view_thread = threading.Thread(target=control.start_view, args=(False,))
    view_thread.start()
    view_thread.join(1)
    while not exit and not control.run_stopped():
        if control.has_selected_interface():
            print("Selected interface: " + control.selectedInterface)
            control.scan_networks()
            print("Start scanning available networks...")
            time.sleep(3)
            while not control.selectedNetwork and control.running_scan() and not control.run_stopped():
                time.sleep(1)
                print("\t... Scanning networks ...")
                if not control.filter_networks():
                    time.sleep(1)
                    control.stop_scan()
                    time.sleep(1)
                    print(" * An error ocurred, please, re-select the interface")
                    control.selectedInterface = ""
                    control.model.interfaces = []
                    while not control.has_selected_interface() and not control.run_stopped():
                        control.scan_interfaces(auto_select)
                        print("Scanning interfaces")
                        time.sleep(1)
                    print("Selected interface: " + control.selectedInterface)
                    control.scan_networks()
                    print("Start scanning available networks...")
                    time.sleep(3)
            print("\n * Network scanning stopped * \n")
            print(control.selectedNetwork)
            print(control.running_scan())
            while not control.selectedNetwork and not control.run_stopped():
                # waits until a network is selected
                time.sleep(1)
            print("Selected network: " + str(control.selectedNetwork))
            print("\nStarting attack...\n")

            while not control.cracking_completed and not control.run_stopped():
                print("\t... Cracking network ...")
                time.sleep(1)

            print("Cracking process finished.")
        else:
            print("Scanning interfaces")
            control.scan_interfaces(auto_select)
            time.sleep(1)
            if control.get_interfaces() == "":
                control.view.show_info_notification("No wireless interfaces found."
                                                    "\n\nPlease connect a wireless card.")

    view_thread.join(0)
