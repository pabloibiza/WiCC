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
    HORIZONTAL, END, FALSE, IntVar, StringVar, messagebox, filedialog, LabelFrame

from wicc_view_right_click import rClicker


class ViewMac:
    main_view = ""
    current_mac = ""
    accepted_characters = ['a', 'b', 'c', 'd', 'e', 'f', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', ':']

    def __init__(self, view, spoofing_status):
        self.main_view = view
        self.spoofing_status = spoofing_status
        self.build_window()
        self.set_spoofing_checkbutton()
        self.root.attributes('-topmost', True)
        self.root.mainloop()

    def build_window(self):
        """
        Generates the window.

        :author: Pablo Sanz Alguacil
        """

        self.root = Toplevel()
        self.root.geometry('440x490')
        self.root.resizable(width=False, height=False)
        self.root.title('WiCC - Mac Changer Tools')

        # LABELFRAME - INFO
        self.labelframe_info = LabelFrame(self.root, text="")
        self.labelframe_info.pack(fill="both", expand="no", pady=15)

        # LABEL - INFO
        self.label_info = Label(self.labelframe_info, pady=15,
                                text="In this window you can change your MAC as you want by"
                                     "\nusing one this options. A great power comes with a"
                                     "\ngreat responsibility")
        self.label_info.pack(side=TOP)

        # LABELFRAME - CUSTOM MAC
        self.labelframe_custom_mac = LabelFrame(self.root, text="Write custom MAC")
        self.labelframe_custom_mac.pack(fill="both", expand="no", pady=10)

        # LABEL - CUSTOM MAC
        self.label_custom_mac = Label(self.labelframe_custom_mac, text="Custom MAC: ")
        self.label_custom_mac.grid(column=1, row=0, padx=5)

        # ENTRY - CUSTOM MAC
        self.entry_custom_mac = ttk.Entry(self.labelframe_custom_mac)
        self.entry_custom_mac.grid(column=2, row=0, padx=8)
        self.entry_custom_mac.bind('<Button-3>', rClicker, add='')

        # BUTTON - CUSTOM MAC
        self.button_custom_mac = ttk.Button(self.labelframe_custom_mac, text="Set custom MAC", command=self.customize_mac)
        self.button_custom_mac.grid(column=4, row=0)

        # LABELFRAME - RANDOM MAC
        self.labelframe_random_mac = LabelFrame(self.root, text="Randomize MAC")
        self.labelframe_random_mac.pack(fill="both", expand="no", pady=10)

        # LABEL - RANDOM MAC
        self.label_random_mac = Label(self.labelframe_random_mac,
                                      text="Changes the current MAC to a completly \nrandom MAC", justify=LEFT)
        self.label_random_mac.grid(column=1, row=0, rowspan=2, padx=5)

        # BUTTON - RANDOM MAC
        self.button_random_mac = ttk.Button(self.labelframe_random_mac, text="Randomize MAC",
                                            command=self.randomize_mac)
        self.button_random_mac.grid(column=3, row=0, padx=5)

        # LABELFRAME - RESTORE ORIGINAL
        self.labelframe_restore_original = LabelFrame(self.root, text="Restore original MAC")
        self.labelframe_restore_original.pack(fill="both", expand="no", pady=10)

        # LABEL - RESTORE ORIGINAL
        self.label_restore_original = Label(self.labelframe_restore_original,
                                            text="Restores the original selected interface's\nMAC address",
                                            justify=LEFT)
        self.label_restore_original.grid(column=1, row=0, padx=5)

        # BUTTON - RESTORE ORIGINAL
        self.button_restore_original = ttk.Button(self.labelframe_restore_original, text="Restore MAC",
                                                  command=self.restore_mac)
        self.button_restore_original.grid(column=3, row=0, padx=5)

        # LABELFRAME - MAC SPOOFING
        self.labelframe_mac_spoofing = LabelFrame(self.root, text="MAC spoofing")
        self.labelframe_mac_spoofing.pack(fill="both", expand="no", pady=10)

        # LABEL - MAC SPOOFING)
        self.label_mac_spoofing = Label(self.labelframe_mac_spoofing,
                                            text="Spoof client's MAC address during attack")
        self.label_mac_spoofing.grid(column=1, row=0, padx=5)

        # CHECKBUTTON - MAC SPOOFING
        self.checkbutton_mac_spoofing = Checkbutton(self.labelframe_mac_spoofing, text="Active", command=self.mac_spoofing)
        self.checkbutton_mac_spoofing.grid(column=3, row=0, padx=5)

        # BUTTON - DONE
        self.button_done = ttk.Button(self.root, text="Done", command= self.destroy_window)
        self.button_done.pack(padx=15, pady=15)

    def customize_mac(self):
        """
        Sends an order to the main view to set the MAC address to the sended one.
        Filters the address before send it (only hexadecimal values).

        :author: Pablo Sanz Alguacil
        """

        address = self.entry_custom_mac.get().lower()
        colon_count = 0
        address_length = len(self.entry_custom_mac.get())
        address_splited = list(address)
        boolean_fg = True
        for character in address_splited:
            if character in self.accepted_characters and address_length == 17:
                if character == ":":
                    colon_count = colon_count + 1
            else:
                boolean_fg = False
        if boolean_fg and colon_count == 5:
            self.notify_view(0, self.entry_custom_mac.get())
        else:
            self.main_view.show_warning_notification("Address not valid")

    def randomize_mac(self):
        """
        Sends an order to the main view to randomize the MAC address.

        :author: Pablo Sanz Alguacil
        """

        self.notify_view(1, "")

    def restore_mac(self):
        """
        Sends an order to the main view to restore the original MAC address.

        :author: Pablo Sanz Alguacil
        """

        self.notify_view(2, "")

    def set_spoofing_checkbutton(self):
        """
        Selects or deselcts the MAC spoofing checkbutton.

        :author: Pablo Sanz Alguacil
        """

        if self.spoofing_status:
            self.checkbutton_mac_spoofing.select()
        else:
            self.checkbutton_mac_spoofing.deselect()

    def mac_spoofing(self):
        """
        Sends an order to the main view to set the MAC spoofing status. Saves the status in a local variable.

        :author: Pablo Sanz Alguacil
        """

        if self.spoofing_status:
            self.spoofing_status = False
            self.notify_view(3, False)
        else:
            self.spoofing_status = True
            self.notify_view(3, True)

    def notify_view(self, operation,value):
        """
        Operation values (int)
        [0] Custom mac
        [1] Random mac
        [2] Restore mac
        [3] Mac spoofing
        Sends and operation and value to the main view.
        :param self:
        :param operation: integer
        :param value: object

        :author: Pablo Sanz Alguacil
        """
        self.main_view.get_notify_childs(operation, value)

    def destroy_window(self):
        """
        Sends the order and words array to the main view.

        :author: Pablo Sanz Alguacil
        """

        self.main_view.disable_window(False)
        self.root.destroy()
