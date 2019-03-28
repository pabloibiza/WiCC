#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    WiCC (Wireless Cracking Camp)
    GUI tool for wireless cracking on WEP and WPA/WPA2 networks.
    Project developed by Pablo Sanz Alguacil and Miguel Yanes Fernández, as the Group Project for the 3rd year of the
    Bachelor of Sicence in Computing in Digital Forensics and CyberSecurity, at TU Dublin - Blanchardstown Campus
"""

from tkinter import *
from tkinter import Tk, ttk, Frame, Button, Label, Entry, Text, Checkbutton, \
    Scale, Listbox, Menu, BOTH, RIGHT, RAISED, N, E, S, W, \
    HORIZONTAL, END, FALSE, IntVar, StringVar, messagebox, filedialog

from wicc_operations import Operation


class View:
    control = ""
    interfaces = ""
    networks = ""
    interfaces_old = []
    networks_old = []
    encryption_types = ('All', 'WEP', 'WPA')
    channels = ('1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14')
    current_mac = "0A:1B:2C:3D:4E:5F"
    new_mac = "5F:4E:3D:2C:1B:0A"

    def __init__(self, control):
        self.control = control

    def build_window(self, headless=False):
        self.root = Tk()
        self.root.protocol("WM_DELETE_WINDOW", self.kill_application)
        self.root.geometry('830x420')
        self.root.resizable(width=True, height=True)
        self.root.title('WiCC - Wifi Cracking Camp')

        # LABEL FRAME - ANALYSIS OPTIONS
        self.labelframe_analysis = LabelFrame(self.root, text="Analysis Options")
        self.labelframe_analysis.pack(fill="both", expand="yes")

        # LABEL FRAME - MORE FILTERS
        self.labelframe_more_options = LabelFrame(self.root, text="More Options")
        self.labelframe_more_options.pack(fill="both", expand="yes")

        # LABEL FRAME - AVAILABLE NETWORKS
        self.labelframe_networks = LabelFrame(self.root, text="Available Networks")
        self.labelframe_networks.pack(fill="both", expand="yes")

        # LABEL FRAME - START
        self.labelframe_start_stop = LabelFrame(self.root, text="Start/Stop")
        self.labelframe_start_stop.pack(fill="both", expand="yes")

        # LABEL - INTERFACES
        self.null_label0 = Message(self.labelframe_analysis, text="")
        self.null_label0.grid(column=0, row=0)
        self.label_interfaces = ttk.Label(self.labelframe_analysis, text="Interface: ")
        self.label_interfaces.grid(column=1, row=0)

        # COMBO BOX - NETWORK INTERFACES
        self.interfaceVar = StringVar()
        self.interfaces_combobox = ttk.Combobox(self.labelframe_analysis, textvariable=self.interfaceVar)
        self.interfaces_combobox['values'] = self.interfaces
        self.interfaces_combobox.bind("<<ComboboxSelected>>")
        self.interfaces_combobox.grid(column=2, row=0)
        self.null_label1 = Message(self.labelframe_analysis, text="")
        self.null_label1.grid(column=3, row=0)

        # LABEL - ENCRYPTIONS
        self.label_encryptions = ttk.Label(self.labelframe_analysis, text="Encryption: ")
        self.label_encryptions.grid(column=4, row=0)

        # COMBO BOX - ENCRYPTOION
        self.encryptionVar = StringVar()
        self.encryption_combobox = ttk.Combobox(self.labelframe_analysis, textvariable=self.encryptionVar)
        self.encryption_combobox['values'] = self.encryption_types
        self.encryption_combobox.current(0)
        self.encryption_combobox.bind("<<ComboboxSelected>>")
        self.encryption_combobox.grid(column=5, row=0)
        self.null_label2 = Message(self.labelframe_analysis, text="")
        self.null_label2.grid(column=6, row=0)

        # CHECKBUTTON - WPS
        self.wps_status = BooleanVar()
        self.wps_checkbox = ttk.Checkbutton(self.labelframe_analysis, text="Only WPS", variable=self.wps_status)
        self.wps_checkbox.grid(column=7, row=0)
        self.null_label3 = Message(self.labelframe_analysis, text="")
        self.null_label3.grid(column=8, row=0)

        # BUTTON - START SCAN
        self.button_start_scan = ttk.Button(self.labelframe_analysis, text='Start scan', command=self.start_scan)
        self.button_start_scan.grid(column=9, row=0)

        # BUTTON - STOP SCAN
        self.null_label9 = Message(self.labelframe_analysis, text="")
        self.null_label9.grid(column=10, row=0)
        self.button_stop_scan = ttk.Button(self.labelframe_analysis, text='Stop scan', command=self.stop_scan)
        self.button_stop_scan.grid(column=11, row=0)

        # LABEL - CHANNELS
        self.null_label4 = Message(self.labelframe_more_options, text="")
        self.null_label4.grid(column=0, row=0)
        self.label_channels = ttk.Label(self.labelframe_more_options, text="Channel: ")
        self.label_channels.grid(column=1, row=0)

        # COMBO BOX - CHANNELS
        self.channelVar = StringVar()
        self.channels_combobox = ttk.Combobox(self.labelframe_more_options, textvariable=self.channelVar)
        self.channels_combobox['values'] = self.channels
        self.channels_combobox.bind("<<ComboboxSelected>>")
        self.channels_combobox.grid(column=2, row=0)
        self.null_label6 = Message(self.labelframe_more_options, text="")
        self.null_label6.grid(column=3, row=0, sticky=W)

        # CHECKBOX - CLIENTS
        self.clients_status = BooleanVar()
        self.clients_checkbox = ttk.Checkbutton(self.labelframe_more_options, text="Only clients",
                                                variable=self.clients_status)
        self.clients_checkbox.grid(column=4, row=0)
        self.null_label7 = Message(self.labelframe_more_options, text="")
        self.null_label7.grid(column=5, row=0)

        # BUTTON - RAMNDOMIZE MAC
        self.button_randomize_mac = ttk.Button(self.labelframe_more_options, text="Randomize MAC",
                                               command=self.randomize_mac)
        self.button_randomize_mac.grid(column=6, row=0)
        self.null_label8 = Message(self.labelframe_more_options, text="")
        self.null_label8.grid(column=7, row=0)

        # BUTTON - CUSTOM WORDLIST
        self.custom_wordlist_path = ttk.Button(self.labelframe_more_options, text="Select wordlist",
                                               command=self.select_custom_wordlist)
        self.custom_wordlist_path.grid(column=8, row=0)

        # BUTTON - GENERATE WORDLIST
        self.null_label10 = Message(self.labelframe_more_options, text="")
        self.null_label10.grid(column=9, row=0)
        self.generate_wordlist = ttk.Button(self.labelframe_more_options, text="Generate wordlist")
        self.generate_wordlist.grid(column=10, row=0)

        # TREEVIEW - NETWORKS
        self.networks_treeview = ttk.Treeview(self.labelframe_networks)
        self.networks_treeview["columns"] = ("id", "bssid_col", "channel_col", "encryption_col", "power_col", "wps_col",
                                             "clients_col")
        self.networks_treeview.column("id", width=60)
        self.networks_treeview.column("bssid_col", width=150)
        self.networks_treeview.column("channel_col", width=60)
        self.networks_treeview.column("encryption_col", width=85)
        self.networks_treeview.column("power_col", width=70)
        self.networks_treeview.column("wps_col", width=60)
        self.networks_treeview.column("clients_col", width=60)

        self.networks_treeview.heading("id", text="ID")
        self.networks_treeview.heading("bssid_col", text="BSSID")
        self.networks_treeview.heading("channel_col", text="CH")
        self.networks_treeview.heading("encryption_col", text="ENC")
        self.networks_treeview.heading("power_col", text="PWR")
        self.networks_treeview.heading("wps_col", text="WPS")
        self.networks_treeview.heading("clients_col", text="CLNTS")

        self.scrollBar = Scrollbar(self.labelframe_networks)
        self.scrollBar.pack(side=RIGHT, fill=Y)
        self.scrollBar.config(command=self.networks_treeview.yview)
        self.networks_treeview.config(yscrollcommand=self.scrollBar.set)

        self.networks_treeview.pack(fill=X)

        # BUTTON - ATTACK
        self.null_label2 = Message(self.labelframe_start_stop, text="")
        self.null_label2.grid(column=0, row=0)
        self.button_select = ttk.Button(self.labelframe_start_stop, text='Attack', command=self.select_network)
        self.button_select.grid(column=1, row=0)
        self.null_label3 = Message(self.labelframe_start_stop, text="")
        self.null_label3.grid(column=2, row=0)

        # FOCUS IN
        self.button_start_scan.focus_set()

        if not headless:
            self.root.mainloop()


    # Sends the selected interface to control
    def start_scan(self):
        self.send_notify(Operation.SELECT_INTERFACE, self.interfaceVar.get())

    # Sends a stop scanning order to control
    def stop_scan(self):
        self.send_notify(Operation.STOP_SCAN, "")

    # Sends the selected network id to Control
    def select_network(self):
        current_item = self.networks_treeview.focus()
        network_id = self.networks_treeview.item(current_item)['values'][0]
        self.send_notify(Operation.SELECT_NETWORK, network_id)

    # Sends and order to kill all processes when X is clicked
    def kill_application(self):
        self.send_notify(Operation.STOP_RUNNING, "")
        self.root.destroy()

    # Sends an order to randomize the interface MAC address
    def randomize_mac(self):
        currentmac_alert = messagebox.askyesno("", "Your current MAC is: " + self.current_mac +
                                               "\n\nAre you sure you want to change it? ")
        print(currentmac_alert)
        if (currentmac_alert == True):
            self.send_notify(Operation.RANDOMIZE_MAC, "")
            new_mac_alert = messagebox.showinfo("", "You new MAC is: " + self.new_mac)
            print(new_mac_alert)
        else:
            pass

    # Shows a window to select a custom worlist to use. Then sends the path to control.
    def select_custom_wordlist(self):
        select_window = filedialog.askopenfilename(parent=self.root, initialdir='/home/$USER', title='Choose file',
                                                   filetypes=[('Text files', '.txt'), ("All files", "*.*")])
        if select_window:
            try:
                self.send_notify(Operation.SELECT_CUSTOM_WORDLIST, select_window)
            except:
                messagebox.showerror("Open Source File", "Failed to read file \n'%s'" % select_window)
                return

    # Filters networks
    ######################(MUST CHANGE WPS ITEM[INDEX]#################################
    def filters(self, network_list):
        new_network_list = network_list
        if (self.wps_status.get() == True):
            print("WPS FILTER ENABLED")
        #    for item in new_network_list:
        #        if(item[9] == "no"):
        #            new_network_list.remove(item)
        if (self.clients_status.get() == True):
            print("CLIENTS FILTER ENABLED")
            for item in new_network_list:
                if (item[16] == "0"):
                    new_network_list.remove(item)
        if (self.channelVar.get() in self.channels):
            print("CHANNELS FILTER ENABLED")
            for item in new_network_list:
                if (item[4] != self.channelVar):
                    new_network_list.remove(item)
        return new_network_list

    def get_notify(self, interfaces, networks):
        if (self.interfaces_old != interfaces):
            self.interfaces_old = interfaces
            interfaces_list = []
            for item in interfaces:
                interfaces_list.append(item[0])
            self.interfaces_combobox['values'] = interfaces_list
            self.interfaces_combobox.update()

        if (self.networks_old != networks):
            self.networks_old = networks
            self.networks_treeview.delete(*self.networks_treeview.get_children())
            for item in networks:
                self.networks_treeview.insert("", END, text=item[13], values=(item[0], item[1], item[4], item[6],
                                                                              item[9] + " dbi", "yes", item[16]))
                self.networks_treeview.update()

    def show_warning_notification(self, message):
        warning_notification = messagebox.showwarning("Warning", message)
        print(warning_notification)

    def show_info_notification(self, message):
        info_notification = messagebox.showinfo("Info", message)
        print(info_notification)

    def send_notify(self, operation, value):
        self.control.get_notify(operation, value)
        return
