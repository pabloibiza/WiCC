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
    HORIZONTAL, END, FALSE, IntVar, StringVar, messagebox as box

from wicc_operations import Operation


class View:
    control = ""
    interfaces = ""
    networks = ""
    interfaces_old = []
    networks_old = []
    encryption_types = ('All', 'WEP', 'WPA')

    def __init__(self, control):
        self.control = control

    def build_window(self):
        self.root = Tk()
        self.root.geometry('820x260')
        self.root.resizable(width=True, height=True)
        self.root.title('WiCC - Wifi Cracking Camp')

        # LABEL FRAME - ANALYSIS OPTIONS
        self.analysis_labelframe = LabelFrame(self.root, text="Analysis Options")
        self.analysis_labelframe.pack(fill="both", expand="no")

        # LABEL FRAME - AVAILABLE NETWORKS
        self.networks_labelframe = LabelFrame(self.root, text="Available Networks")
        self.networks_labelframe.pack(fill="both", expand="no")

        #LABEL - INTERFACES
        self.label_interfaces = ttk.Label(self.analysis_labelframe, text="Interface: ")
        self.label_interfaces.pack(side=LEFT)

        # COMBO BOX - NETWORK INTERFACES
        self.interfaceVar = StringVar()
        self.interfaces_combobox = ttk.Combobox(self.analysis_labelframe, textvariable=self.interfaceVar)
        self.interfaces_combobox['values'] = self.interfaces
        self.interfaces_combobox.bind("<<ComboboxSelected>>", self.print_parameters)
        self.interfaces_combobox.pack(side=LEFT)

        # LABEL - INTERFACES
        self.label_encryptions = ttk.Label(self.analysis_labelframe, text="Encryption: ")
        self.label_encryptions.pack(side=LEFT)

        # COMBO BOX - ENCRYPTOION
        self.encryptionVar = StringVar()
        self.encryption_combobox = ttk.Combobox(self.analysis_labelframe, textvariable=self.encryptionVar)
        self.encryption_combobox['values'] = self.encryption_types
        self.encryption_combobox.current(0)
        self.encryption_combobox.bind("<<ComboboxSelected>>", self.print_parameters)
        self.encryption_combobox.pack(side=LEFT)

        # BUTTON - SEARCH
        self.search_button = ttk.Button(self.analysis_labelframe, text='Search', command=self.select_interface)
        self.search_button.pack(side=RIGHT)

        # TREEVIEW - NETWORKS
        self.networks_treeview = ttk.Treeview(self.networks_labelframe)
        self.networks_treeview["columns"] = ("id","bssid_col", "channel_col", "encryption_col", "power_col", "wps_col", "clients_col")
        self.networks_treeview.column("id", width=60)
        self.networks_treeview.column("bssid_col", width=150)
        self.networks_treeview.column("channel_col", width=60)
        self.networks_treeview.column("encryption_col", width=70)
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
        self.networks_treeview.pack(side=LEFT, fill=Y)

        self.scrollBar = Scrollbar(self.networks_labelframe)
        self.scrollBar.pack(side=RIGHT, fill=Y)
        self.scrollBar.config(command=self.networks_treeview.yview)
        self.networks_treeview.config(yscrollcommand=self.scrollBar.set)

        # BUTTON - SELECT A NETWORK
        self.button_select = ttk.Button(self.networks_labelframe, text='Attack', command=self.select_network)
        self.button_select.pack(side=BOTTOM)

        # FOCUS IN...
        self.search_button.focus_set()

        self.root.mainloop()

    # Prints current paramers selected in both combo boxes (interface and encryption)
    def print_parameters(self, event):
        selected_parameters = (self.interfaceVar.get(), self.encryptionVar.get())
        print(selected_parameters)

    # Sends the selected interface to control
    def select_interface(self):
        self.send_notify(Operation.SELECT_INTERFACE, self.encryptionVar.get())

    # Sends the selected network id to Control
    def select_network(self):
        current_item = self.networks_treeview.focus()
        network_id = self.networks_treeview.item(current_item)['vaules'][0]
        self.send_notify(Operation.SELECT_NETWORK, network_id)

    def get_notify(self, interfaces, networks):
        if(self.interfaces_old != interfaces):
            self.interfaces_old = interfaces
            interfaces_list = []
            for item in interfaces:
                self.interfaces_list.append(item[0])
            self.interfaces_combobox['values'] = interfaces_list
            self.interfaces_combobox.update()

        if(self.networks_old != networks):
            self.networks_old = networks
            self.networks_treeview.delete(*self.networks_treeview.get_children())
            for item in networks:
                self.networks_treeview.insert("", END, text=item[13], values=(item[0], item[1], item[4], item[6], item[9] + " dbi", "yes", "client"))
                self.networks_treeview.update()

    def send_notify(self, operation, value):
        self.control.get_notify(operation, value)
        return
