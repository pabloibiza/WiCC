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

class View:
    control = ""
    interfaces = ""
    networks = ""

    def __init__(self, control):
        self.control = control

        self.root = Tk()
        self.root.geometry('600x230')
        self.root.resizable(width=True, height=True)
        self.root.title('WiCC - Wifi Cracking Camp')

        # LABEL FRAME - ANALYSIS OPTIONS
        self.analysis_labelframe = LabelFrame(self.root, text="Analysis Options")
        self.analysis_labelframe.pack(fill="both", expand="no")

        # LABEL FRAME - AVAILABLE NETWORKS
        self.networks_labelframe = LabelFrame(self.root, text="Available Networks")
        self.networks_labelframe.pack(fill="both", expand="no")

        # COMBO BOX - NETWORK INTERFACES
        self.interfaceVar = StringVar()
        self.interfaces_combobox = ttk.Combobox(self.analysis_labelframe, textvariable=self.interfaceVar)
        interfaces = ('wlan0', 'wlan1', 'wlan2')
        self.interfaces_combobox['values'] = interfaces
        self.interfaces_combobox.current(1)
        self.interfaces_combobox.bind("<<ComboboxSelected>>", self.print_parameters)
        self.interfaces_combobox.pack(side=LEFT)

        # COMBO BOX - ENCRYPTOION
        self.encryptionVar = StringVar()
        self.encryption_combobox = ttk.Combobox(self.analysis_labelframe, textvariable=self.encryptionVar)
        self.encryption_combobox['values'] = ('WEP', 'WPA', 'Both')
        self.encryption_combobox.current(1)
        self.encryption_combobox.bind("<<ComboboxSelected>>", self.print_parameters)
        self.encryption_combobox.pack(side=LEFT)

        # BUTTON - SEARCH
        self.search_button = ttk.Button(self.analysis_labelframe, text='Search')
        self.search_button.pack(side=RIGHT)

        # TREEVIEW - NETWORKS
        self.list = (('Zero', '0A', '0B'), ('One', '1A', '1B'), ('Two', '2A', '2B'), ('Three', '3A', '3B'),
                     ('Four', '4A', '4B'), ('Five', '5A', '5B'), ('Six', '6A', '6B'), ('Seven', '7A', '7B'))

        self.networks_treeview = ttk.Treeview(self.networks_labelframe)
        self.networks_treeview["columns"] = ("one", "two")
        self.networks_treeview.column("one", width=100)
        self.networks_treeview.column("two", width=100)
        self.networks_treeview.heading("one", text="coulmn A")
        self.networks_treeview.heading("two", text="column B")
        self.networks_treeview.pack(side=LEFT, fill=Y)

        self.scrollBar = Scrollbar(self.networks_labelframe)
        self.scrollBar.pack(side=RIGHT, fill=Y)
        self.scrollBar.config(command=self.networks_treeview.yview)
        self.networks_treeview.config(yscrollcommand=self.scrollBar.set)

        for item in self.list:
            self.networks_treeview.insert("", END, text=item[0], values=(item[1], item[2]))

        # BUTTON - PRINT SELECTED LINE
        self.print_button = Button(self.networks_labelframe, text='Print', command=self.print_selected)
        self.print_button.pack(side=BOTTOM)

        # FOCUS IN...
        self.search_button.focus_set()

        self.root.mainloop()

        # Prints current paramers selected in both combo boxes (interface and encryption)

    def print_parameters(self, event):
        selected_parameters = (self.interfaceVar.get(), self.encryptionVar.get())
        print(selected_parameters)

        # Prints the selected item from the treeview widget

    def print_selected(self):
        currentItem = self.networks_treeview.focus()
        print(self.networks_treeview.item(currentItem)['values'])


    def get_notify(self, interfaces, networks):
        self.interfaces = interfaces
        self.networks = networks

    def send_notify(self, operation, value):
        self.control.get_notify(operation, value)

def main():
    mi_app = View()
    return 0


if __name__ == '__main__':
    main()