#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    WiCC (Wireless Cracking Camp)
    GUI tool for wireless cracking on WEP and WPA/WPA2 networks.
    Project developed by Pablo Sanz Alguacil and Miguel Yanes Fernández, as the Group Project for the 3rd year of the
    Bachelor of Sicence in Computing in Digital Forensics and CyberSecurity, at TU Dublin - Blanchardstown Campus
"""

import webbrowser
from tkinter import *
from tkinter import Tk, ttk, Frame, Button, Label, Checkbutton, Menu, RIGHT, N, E, S, W, END, StringVar,\
    messagebox, filedialog
from wicc_operations import Operation
from wicc_view_crunch import GenerateWordlist
from wicc_view_mac import ViewMac
from wicc_view_splash import Splash
from wicc_view_popup import PopUpWindow
from wicc_view_about import About


class View:
    control = ""
    interfaces = ""
    networks = ""
    width = 850
    height = 470
    interfaces_old = []
    networks_old = []
    encryption_types = ('ALL', 'WEP', 'WPA')
    channels = ('ALL', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14')
    mac_spoofing_status = False
    silent_mode_status = False
    icon_path = "Resources/icon.png"
    file_icon_path = "Resources/file_icon.png"
    tools_icon_path = "Resources/tools_icon.png"
    help_icon_path = "Resources/help_icon.png"

    def __init__(self, control):
        self.control = control
        self.splash = Splash()
        self.popup_gen = PopUpWindow()

    def build_window(self, headless=False, splash_image=True):
        """
        Generates the window.
        :param headless:
        :param splash_image: False to don't show the splash image

        :author: Pablo Sanz Alguacil
        """

        self.root = Tk()
        self.root.protocol("WM_DELETE_WINDOW", self.notify_kill)
        self.root.style = ttk.Style()
        self.root.style.theme_use('default')
        # get screen width and height
        ws = self.root.winfo_screenwidth()
        hs = self.root.winfo_screenheight()
        # calculate position x, y
        x = (ws / 2) - (self.width / 2)
        y = (hs / 2) - (self.height / 2)
        self.root.geometry('%dx%d+%d+%d' % (self.width, self.height, x, y))
        self.root.resizable(width=False, height=False)
        self.root.title('WiCC - Wifi Cracking Camp')
        icon = Image("photo", file=self.icon_path)
        self.root.call('wm', 'iconphoto', self.root._w, icon)

        # MENU BAR
        self.menubar = Menu(self.root)
        self.root['menu'] = self.menubar

        self.menu1 = Menu(self.menubar)
        self.menu2 = Menu(self.menubar)
        self.menu3 = Menu(self.menubar)
        self.menubar.add_cascade(menu=self.menu1, label='File')
        self.menubar.add_cascade(menu=self.menu2, label='Tools')
        self.menubar.add_cascade(menu=self.menu3, label='Help')

        # MENU 1
        self.menu1.add_command(label='Temporary files location',
                               command=self.temporary_files_location,
                               underline=0,
                               compound=LEFT)

        self.menu1.add_command(label='Exit',
                               command=self.notify_kill,
                               underline=0,
                               compound=LEFT)

        # MENU 2
        self.menu2.add_command(label='MAC menu',
                               command=self.mac_tools_window,
                               underline=0,
                               compound=LEFT)

        self.menu2.add_command(label='Select wordlist',
                               command=self.select_custom_wordlist,
                               underline=0,
                               compound=LEFT)

        self.menu2.add_command(label='Generate wordlist',
                               command=self.generate_wordlists_window,
                               underline=0,
                               compound=LEFT)

        # MENU 3
        self.menu3.add_command(label='Help',
                               command=self.open_link,
                               underline=0,
                               compound=LEFT)

        self.menu3.add_command(label='About',
                               command=self.show_about,
                               underline=0,
                               compound=LEFT)

        # LABEL FRAME - SCAN
        self.labelframe_scan = LabelFrame(self.root, text="Scan")
        self.labelframe_scan.pack(fill="both", expand="yes")

        # LABEL FRAME - FILTERS
        self.labelframe_filters = LabelFrame(self.root, text="Filters")
        self.labelframe_filters.pack(fill="both", expand="yes")

        # LABEL FRAME - AVAILABLE NETWORKS
        self.labelframe_networks = LabelFrame(self.root, text="Available Networks")
        self.labelframe_networks.pack(fill="both", expand="yes")

        # LABEL FRAME - SELECT NETWORK NETWORK
        self.labelframe_sel_net = LabelFrame(self.root, text="")
        self.labelframe_sel_net.pack(fill="both", expand="yes")
        self.labelframe_sel_net.grid_columnconfigure(1, weight=1)

        # LABEL FRAME - ATTACK OPTIONS
        self.labelframe_attack_options = LabelFrame(self.root, text="Attack Options")
        self.labelframe_attack_options.pack(fill="both", expand="yes")

        # LABEL FRAME - WEP
        self.labelframe_wep = LabelFrame(self.root, text="WEP Attack Options")

        # LABEL FRMAE - WPA
        self.labelframe_wpa = LabelFrame("", text="WPA Attack Options")

        # LABEL - INTERFACES
        self.label_interfaces = Label(self.labelframe_scan, text="Interface: ")
        self.label_interfaces.grid(column=1, row=0, padx=5)

        # COMBO BOX - NETWORK INTERFACES
        self.interfaceVar = StringVar()
        self.interfaces_combobox = ttk.Combobox(self.labelframe_scan, textvariable=self.interfaceVar)
        self.interfaces_combobox['values'] = self.interfaces
        self.interfaces_combobox.bind("<<ComboboxSelected>>")
        self.interfaces_combobox.grid(column=2, row=0)

        # FRAME - START/STOP SCAN
        self.frame_start_stop = Frame(self.labelframe_scan)
        self.frame_start_stop.grid(column=3, row=0, padx=380, pady=5)

        # BUTTON - START SCAN
        self.button_start_scan = Button(self.frame_start_stop, text='Start scan', command=self.start_scan)
        self.button_start_scan.grid(column=1, row=0, padx=5)

        # BUTTON - STOP SCAN
        self.button_stop_scan = Button(self.frame_start_stop, text='Stop scan', state=DISABLED,
                                       command=self.stop_scan)
        self.button_stop_scan.grid(column=2, row=0, padx=5)

        # LABEL - CHANNELS
        self.label_channels = Label(self.labelframe_filters, text="Channel: ", padx=10, pady=10)
        self.label_channels.grid(column=1, row=0)

        # COMBO BOX - CHANNELS
        self.channelVar = StringVar()
        self.channels_combobox = ttk.Combobox(self.labelframe_filters, textvariable=self.channelVar)
        self.channels_combobox['values'] = self.channels
        self.channels_combobox.bind("<<ComboboxSelected>>")
        self.channels_combobox.current(0)
        self.channels_combobox.grid(column=2, row=0)

        # LABEL - ENCRYPTIONS
        self.label_encryptions = Label(self.labelframe_filters, text="Encryption: ")
        self.label_encryptions.grid(column=3, row=0, padx=5)

        # COMBO BOX - ENCRYPTOION
        self.encryptionVar = StringVar()
        self.encryption_combobox = ttk.Combobox(self.labelframe_filters, textvariable=self.encryptionVar)
        self.encryption_combobox['values'] = self.encryption_types
        self.encryption_combobox.current(0)
        self.encryption_combobox.bind("<<ComboboxSelected>>")
        self.encryption_combobox.grid(column=4, row=0)

        # CHECKBOX - CLIENTS
        self.clients_status = BooleanVar()
        self.clients_checkbox = Checkbutton(self.labelframe_filters, text="Only clients",
                                            variable=self.clients_status)
        self.clients_checkbox.grid(column=5, row=0, padx=15)

        # TREEVIEW - NETWORKS
        self.networks_treeview = ttk.Treeview(self.labelframe_networks)
        self.networks_treeview["columns"] = ("id", "bssid_col", "channel_col", "encryption_col", "power_col",
                                             "clients_col")
        self.networks_treeview.column("id", width=60)
        self.networks_treeview.column("bssid_col", width=150)
        self.networks_treeview.column("channel_col", width=60)
        self.networks_treeview.column("encryption_col", width=85)
        self.networks_treeview.column("power_col", width=70)
        self.networks_treeview.column("clients_col", width=60)

        self.networks_treeview.heading("id", text="ID")
        self.networks_treeview.heading("bssid_col", text="BSSID")
        self.networks_treeview.heading("channel_col", text="CH")
        self.networks_treeview.heading("encryption_col", text="ENC")
        self.networks_treeview.heading("power_col", text="PWR")
        self.networks_treeview.heading("clients_col", text="CLNTS")

        self.scrollBar = Scrollbar(self.labelframe_networks)
        self.scrollBar.pack(side=RIGHT, fill=Y)
        self.scrollBar.config(command=self.networks_treeview.yview)
        self.networks_treeview.config(yscrollcommand=self.scrollBar.set)

        self.networks_treeview.pack(fill=X)

        # BUTTON - SELECT NETWORK
        self.button_select_network = Button(self.labelframe_sel_net, text="Select network",
                                            command=self.select_network)
        self.button_select_network.grid(column=1, row=0, padx=5, pady=5, sticky=W + E + N + S)

        # CHECKBUTTON - SILENT MODE
        self.checkbutton_silent = Checkbutton(self.labelframe_sel_net, text="Silent Mode",
                                              command=self.silent_mode)
        self.checkbutton_silent.grid(column=2, row=0, padx=5, pady=5, sticky=W)

        # CHECKBUTTON - SILENT MODE
        self.button_select_wordlist = Button(self.labelframe_sel_net, text=" Select wordlist",
                                              command=self.select_custom_wordlist)
        self.button_select_wordlist.grid(column=3, row=0, padx=5, pady=5, sticky=W)

        # LABEL - NULL LABEL
        self.null_label = Label(self.labelframe_attack_options, text=" ")
        self.null_label.grid(column=0, row=0, padx=5)

        # BUTTON - START ATTACK WEP
        self.button_start_attack_wep = Button(self.labelframe_wep, text='Attack', command=self.start_attack)
        self.button_start_attack_wep.grid(column=0, row=0, padx=5)

        # BUTTON - STOP ATTACK WEP
        self.button_stop_attack_wep = Button(self.labelframe_wep, text='Stop Attack', command=self.stop_attack)
        self.button_stop_attack_wep.grid(column=1, row=0, padx=5)

        # BUTTON - SCAN WPA
        self.button_scan_wpa = Button(self.labelframe_wpa, text="Scan", command=self.start_scan_wpa)
        self.button_scan_wpa.grid(column=0, row=0, padx=5)

        # BUTTON - STOP SCAN WPA
        self.button_stop_scan_wpa = Button(self.labelframe_wpa, text="Stop scan", command=self.stop_scan_wpa)
        self.button_stop_scan_wpa.grid(column=1, row=0, padx=5)

        # BUTTON - START ATTACK WPA
        self.button_start_attack_wpa = Button(self.labelframe_wpa, text='Attack', command=self.start_attack)
        self.button_start_attack_wpa.grid(column=2, row=0, padx=5)

        # BUTTON - STOP ATTACK WPA
        self.button_stop_attack_wpa = Button(self.labelframe_wpa, text='Stop Attack', command=self.stop_attack)
        self.button_stop_attack_wpa.grid(column=3, row=0, padx=5)

        if not headless:
            self.root.mainloop()

    def select_network(self):
        try:
            current_item = self.networks_treeview.focus()
            network_enc = self.networks_treeview.item(current_item)['values'][3]
            network_id = self.networks_treeview.item(current_item)['values'][0]
            self.labelframe_attack_options.pack_forget()
            if "WEP" in network_enc:
                self.labelframe_wpa.pack_forget()
                self.labelframe_wep.pack(fill="both", expand="yes")
            elif "WPA" in network_enc:
                self.labelframe_wep.pack_forget()
                self.labelframe_wpa.pack(fill="both", expand="yes")
            elif network_enc == "OPN":
                self.popup_gen.popup_info("No valid", "This network is open")

            self.send_notify(Operation.SELECT_NETWORK, network_id)

        except:
            self.popup_gen.popup_error("Error", "No network selected")

    def start_scan(self):
        """
        Sends filters to Control and the sends the selected interface to Control to start scanning.
        Activates button dehabilitation.

        :author: Pablo Sanz Alguacil
        """

        self.set_buttons(False)
        self.send_notify(Operation.SCAN_OPTIONS, self.apply_filters())
        self.send_notify(Operation.SELECT_INTERFACE, self.interfaceVar.get())

    def stop_scan(self):
        """
        Sends the stop scannig order to Control.
        Deactivates buttons dehabilitation.

        :author: Pablo Sanz Alguacil
        """

        self.set_buttons(True)
        self.send_notify(Operation.STOP_SCAN, "")

    def set_buttons(self, status):
        """
        Sets all buttons state to "ACTIVE" or "DISABLED".

        :param status: boolean
        :author: Pablo Sanz Alguacil
        """
        if status:
            state = ACTIVE
            self.button_stop_scan['state'] = DISABLED
            self.menubar.entryconfig("File", state="normal")
            self.menubar.entryconfig("Tools", state="normal")
            self.menubar.entryconfig("Help", state="normal")
        else:
            state = DISABLED
            self.button_stop_scan['state'] = ACTIVE
            self.menubar.entryconfig("File", state="disabled")
            self.menubar.entryconfig("Tools", state="disabled")
            self.menubar.entryconfig("Help", state="disabled")

        self.interfaces_combobox['state'] = state
        self.encryption_combobox['state'] = state
        self.channels_combobox['state'] = state
        self.clients_checkbox['state'] = state
        self.button_start_scan['state'] = state
        self.button_select_network['state'] = state
        self.checkbutton_silent['state'] = state
        self.button_start_attack_wep['state'] = state
        self.button_stop_attack_wep['state'] = state
        self.button_scan_wpa['state'] = state
        self.button_stop_scan_wpa['state'] = state
        self.button_start_attack_wpa['state'] = state
        self.button_stop_attack_wpa['state'] = state
        self.checkbutton_silent['state'] = state
        self.button_select_wordlist['state'] = state

    def start_attack(self):
        """
        Sends the selected network id to Control, to start the attack.

        :author: Pablo Sanz Alguacil
        """

        current_item = self.networks_treeview.focus()
        network_id = self.networks_treeview.item(current_item)['values'][0]
        self.send_notify(Operation.ATTACK_NETWORK, network_id)

    def notify_kill(self):
        """
        Sends and order to kill all processes when X is clicked

        :author: Pablo Sanz Alguacil
        """

        self.send_notify(Operation.STOP_RUNNING, "")

    def reaper_calls(self):
        """
        Receives a notification to kill root

        :author: Pablo Sanz Alguacil
        """

        self.root.destroy()

    def select_custom_wordlist(self):
        """
        Shows a window to select a custom wordlist to use. Then sends the path to control.

        :author: Pablo Sanz Alguacil
        """
        select_window = filedialog.askopenfilename(parent=self.root,
                                                   initialdir='/home/$USER',
                                                   title='Choose wordlist file',
                                                   filetypes=[('Text files', '.txt'),
                                                              ('List files', '.lst'),
                                                              ("All files", "*.*")])
        if select_window:
            try:
                self.send_notify(Operation.SELECT_CUSTOM_WORDLIST, select_window)
            except:
                messagebox.showerror("Open Source File", "Failed to read file \n'%s'" % select_window)
                return

    def randomize_mac(self):
        """
        Generates a popup window asking for authorisation to change the MAC, then sends the randomize order to Control,
        and shows another popup showing the new MAC.

        :author: Pablo Sanz Alguacil
        """
        if self.interfaceVar.get() != "":
            currentmac_alert = messagebox.askyesno("", "Your current MAC is: " + self.current_mac()
                                                   + "\n\nAre you sure you want to change it? ")
            if currentmac_alert == True:
                self.send_notify(Operation.RANDOMIZE_MAC, self.interfaceVar.get())
                new_mac_alert = messagebox.showinfo("", "Your new MAC is: " + self.current_mac())
        else:
            self.show_warning_notification("No interface selected. Close the window and select one")

    def customize_mac(self, new_mac):
        """
        Generates a popup window asking for authorisation to change the MAC, then sends the customize order to Control,
        and shows another popup showing the new MAC.
        :param new_mac: new MAC to be set

        :author: Pablo Sanz Alguacil
        """

        if self.interfaceVar.get() != "":
            currentmac_alert = messagebox.askyesno("", "Your current MAC is: " + self.current_mac()
                                                   + "\n\nAre you sure you want to change it for\n" +
                                                   new_mac + " ?")
            if currentmac_alert == True:
                self.send_notify(Operation.CUSTOMIZE_MAC, (self.interfaceVar.get(), new_mac))
                new_mac_alert = messagebox.showinfo("", "Your new MAC is: " + self.current_mac())
        else:
            self.show_warning_notification("No interface selected. Close the window and select one")

    def restore_mac(self):
        """
        Generates a popup window asking for authorisation to restore the MAC, then sends the restore order to Control,
        and shows another popup showing the new MAC.

        :author: Pablo Sanz Alguacil
        """

        if self.interfaceVar.get() != "":
            currentmac_alert = messagebox.askyesno("", "Your current MAC is: " + self.current_mac()
                                                   + "\n\nAre you sure you want to restore original?")
            if currentmac_alert == True:
                self.send_notify(Operation.RESTORE_MAC, self.interfaceVar.get())
                new_mac_alert = messagebox.showinfo("", "Your new MAC is: " + self.current_mac())
        else:
            self.show_warning_notification("No interface selected. Close the window and select one")

    def spoofing_mac(self, status):
        """
        Sends the order to activate MAC spoofing to Control.
        :param status: current status of MAC spoofing

        :author: Pablo Sanz Alguacil
        """

        if self.interfaceVar.get() != "":
            self.send_notify(Operation.SPOOF_MAC, status)
        else:
            self.show_warning_notification("No interface selected. Close the window and select one")

    def mac_tools_window(self):
        """
        Generates the MAC tools window.
        Activates buttons dehabilitation.

        :author: Pablo Sanz Alguacil
        """

        self.disable_window(True)
        ViewMac(self, self.mac_spoofing_status)

    # Filters networks
    """
    [0]ENCRYPTION (string)
    [1]WPS (boolean)
    [2]CLIENTS (boolean)
    [3]CHANNEL (string)
    """

    def apply_filters(self):
        """
        [0]ENCRYPTION (string)
        [1]WPS (boolean)
        [2]CLIENTS (boolean)
        [3]CHANNEL (string)
        Sets the filters parameters depending on the options choosed.
        :return: array containing filter parameters

        :author: Pablo Sanz Alguacil
        """

        filters_status = ["ALL", False, False, "ALL"]
        if self.encryptionVar.get() != "ALL":
            filters_status[0] = self.encryptionVar.get()
        if self.clients_status.get() == True:
            filters_status[2] = True
        if self.channelVar.get() != "ALL":
            filters_status[3] = self.channelVar.get()
        return filters_status

    def get_notify(self, interfaces, networks):
        """
        Introduces the interfaces and networks received in their respective structures.
        :param interfaces: array containing strings of the interfaces names.
        :param networks: array containing the networks and its properties.

        :author: Pablo Sanz Alguacil
        """

        if interfaces:
            self.interfaces_old = interfaces
            interfaces_list = []
            for item in interfaces:
                interfaces_list.append(item[0])
            self.interfaces_combobox['values'] = interfaces_list
            self.interfaces_combobox.update()

        if self.networks_old != networks:
            self.networks_old = networks
            self.networks_treeview.delete(*self.networks_treeview.get_children())
            for item in networks:
                self.networks_treeview.insert("", END, text=item[13], values=(item[0], item[1], item[4], item[6],
                                                                              item[9] + " dbi", "yes", item[16]))
                self.networks_treeview.update()

    def current_mac(self):
        """
        Gets the current MAC from Control.
        :return: string containing the MAC address

        :author: Pablo Sanz Alguacil
        """

        return str(self.control.mac_checker(self.interfaceVar.get()))

    def get_notify_childs(self, operation, value):
        """
        [0] Custom MAC
        [1] Random MAC
        [2] Restore MAC
        [3] MAC spoofing
        [4] Save directory to generated wordlists
        [5] Generate wordlist
        Manages the operations received by the child windows (MAC tools, Crunch window)
        :param operation: integer. Is the id of the operation.
        :param value: value of the operation

        :author: Pablo Sanz Alguacil
        """

        if operation == 0:
            self.customize_mac(value)
        elif operation == 1:
            self.randomize_mac()
        elif operation == 2:
            self.restore_mac()
        elif operation == 3:
            self.mac_spoofing_status = value
            self.spoofing_mac(value)
        elif operation == 4:
            self.send_notify(Operation.PATH_GENERATED_LISTS, value)
        elif operation == 5:
            self.send_notify(Operation.GENERATE_LIST, value)

    def get_spoofing_status(self):
        """
        Gets the current spoofing status.
        :return: boolean

        :author: Pablo Sanz Alguacil
        """

        return self.mac_spoofing_status

    ##########################################
    # SET NOTIFICATIONS TITLES AS PARAMETERS #
    ##########################################
    def show_warning_notification(self, message):
        """
        Shows a warning popup window with a custom message.
        :param message: string containing the message

        :author: Pablo Sanz Alguacil
        """
        warning_notification = messagebox.showwarning("Warning", message)
        self.root.update()
        print(warning_notification)

    ##########################################
    # SET NOTIFICATIONS TITLES AS PARAMETERS #
    ##########################################
    def show_info_notification(self, message):
        """
        Shows a info popup window with a custom message.
        :param message: string containing the message

        :author: Pablo Sanz Alguacil
        """

        info_notification = messagebox.showinfo("Info", message)
        self.root.update()
        print(info_notification)

    def send_notify(self, operation, value):
        """
        Sends an order to Control
        :param operation: Opertaion from Operations class
        :param value: value of the operation
        :return:

        :author: Pablo Sanz Alguacil
        """

        self.control.get_notify(operation, value)
        return

    def disable_window(self, value):
        """
        Disables all buttons
        :param value: boolean. True for disable, False for enable.

        :author: Pablo Sanz Alguacil
        """

        if value:
            self.set_buttons(False)
            self.button_stop_scan['state'] = DISABLED
        elif not value:
            self.set_buttons(True)

    def generate_wordlists_window(self):
        """
        Generates the custom wordlists generator window.

        :author: Pablo Sanz Alguacil
        """

        self.disable_window(True)
        GenerateWordlist(self)

    def temporary_files_location(self):
        """
        Shows a window to select a location to save temporary files. Then sends the path to control.

        :author: Pablo Sanz Alguacil
        """

        select_window = filedialog.askdirectory(parent=self.root,
                                                initialdir='/home',
                                                title='Choose directory')
        if select_window:
            try:
                self.send_notify(Operation.SELECT_TEMPORARY_FILES_LOCATION, select_window)
            except:
                messagebox.showerror("Error", "Failed to set directory \n'%s'" % select_window)
                return

    def stop_attack(self):
        """
        Sends a notification to control so stop the current attack.

        :author: Pablo Sanz Alguacil
        """

        self.send_notify(Operation.STOP_ATTACK, "")

    def start_scan_wpa(self):
        """
        Sends a notification to start a WPA scan.

        :author: Pablo Sanz Alguacil
        """

        self.send_notify(Operation.START_SCAN_WPA, "")

    def stop_scan_wpa(self):
        """
        Sends a notification to stop the WPA scan.

        :author: Pablo Sanz Alguacil
        """

        self.send_notify(Operation.STOP_SCAN_WPA, "")

    def silent_mode(self):
        """
        Sends an order to control to set or unset the silent mode. Saves the status in a local variable.

        :author: Pablo Sanz Alguacil
        """

        if self.silent_mode_status:
            self.silent_mode_status = False
            self.send_notify(Operation.SILENT_SCAN, False)
        else:
            self.silent_mode_status = True
            self.send_notify(Operation.SILENT_SCAN, True)

    def get_notify_buttons(self, buttons, state):
        """
        Gets a notification to enable or disable buttons from the wep and wpa labelframes.
        :param buttons: Array[String] names of the buttons to be dissabled.
        :param state: boolean

        :author: Pablo Sanz Alguacil
        """

        if state:
            status = ACTIVE
        else:
            status = DISABLED

        for button in buttons:
            if button == "scan_wpa":
                self.button_scan_wpa['state'] = status
            elif button == "stop_scan_wpa":
                self.button_stop_attack_wpa['state'] = status
            elif button == "attack_wpa":
                self.button_start_attack_wpa['state'] = status
            elif button == "stop_attack_wpa":
                self.button_stop_attack_wpa['state'] = status
            elif button == "attack_wep":
                self.button_start_attack_wep['state'] = status
            elif button == "stop_attack_wep":
                self.button_stop_attack_wep['state'] = status

    def show_about(self):
        """
        Creates a new About object

        :author: Pablo Sanz Alguacil
        """
        About()

    def open_link(event):
        """
        Opens the URL on a new tab in the default web browser.

        :author: Pablo Sanz Alguacil
        """

        url = "http://www.github.com/pabloibiza/WiCC"
        webbrowser.open_new_tab(url)
