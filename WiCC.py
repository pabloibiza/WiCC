from wicc_control import Control
import sys
import os
import time

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
                elif i == 3:
                    print("\t***Missing cowpatty")

        print("\n")
        sys.exit(1)

    exit = False
    while not exit:
        if control.has_selected_interface():
            control.scan_networks()
            # Process(target=control.scan_networks()).start()
            # scan_process.start()
            # scan_process.join()
            print("scanning networks")
            print("filtering networks")
            time.sleep(3)
            while not control.selectedNetwork != "":
                time.sleep(1)
                print("**************************************************\n****************start filtering"
                      "*******************\n**************************************************")
                control.filter_networks("/tmp/WiCC/net_scan")
            sys.exit(0)
        else:
            control.scan_interfaces()
        time.sleep(1)
