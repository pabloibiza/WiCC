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


class ViewMac:
    main_view = ""
    current_mac = ""

    def __init__(self, view):
        self.main_view = view
        self.build_window()
        self.root.mainloop()

    def build_window(self):
        self.root = Tk()
        self.root.geometry('440x490')
        self.root.resizable(width=False, height=False)
        self.root.title('WiCC - Mac Changer Tools')

        # LABELFRAME - CURRENT MAC
        self.labelframe_current_mac = LabelFrame(self.root, text="")
        self.labelframe_current_mac.pack(fill="both", expand="no")

        # LABEL - SHOW MAC
        self.null_label10 = Message(self.labelframe_current_mac, text="")
        self.null_label10.pack(side=TOP)
        self.label_mac = Label(self.labelframe_current_mac, text="In this window you can change your MAC as you want by"
                                                                 "\nusing one this options. A great power comes with a"
                                                                 "\ngreat responsibility")
        self.label_mac.pack(side=TOP)
        self.null_label13 = Message(self.labelframe_current_mac, text="")
        self.null_label13.pack(side=TOP)

        # LABELFRAME - CUSTOM MAC
        self.null_label11 = Message(self.root, text="")
        self.null_label11.pack()
        self.labelframe_custom_mac = LabelFrame(self.root, text="Write custom MAC")
        self.labelframe_custom_mac.pack(fill="both", expand="no")

        # LABEL - CUSTOM MAC
        self.null_label0 = Message(self.labelframe_custom_mac, text="")
        self.null_label0.grid(column=0, row=0)
        self.label_custom_mac = Label(self.labelframe_custom_mac, text="Custom MAC: ")
        self.label_custom_mac.grid(column=1, row=0)

        # ENTRY - CUSTOM MAC
        self.entry_custom_mac = ttk.Entry(self.labelframe_custom_mac)
        self.entry_custom_mac.grid(column=2, row=0)
        self.null_label1 = Message(self.labelframe_custom_mac, text="   ")
        self.null_label1.grid(column=3, row=0)

        # BUTTON - CUSTOM MAC
        self.button_custom_mac = ttk.Button(self.labelframe_custom_mac, text="Set custom MAC", command=self.customize_mac)
        self.button_custom_mac.grid(column=4, row=0)

        # LABELFRAME - RANDOM MAC
        self.null_label12 = Message(self.root, text="")
        self.null_label12.pack()
        self.labelframe_random_mac = LabelFrame(self.root, text="Randomize MAC")
        self.labelframe_random_mac.pack(fill="both", expand="no")

        # LABEL - RANDOM MAC
        self.null_label2 = Message(self.labelframe_random_mac, text="")
        self.null_label2.grid(column=0, row=0)
        self.label_random_mac = Label(self.labelframe_random_mac,
                                      text="Changes the current MAC to a completly \nrandom MAC")
        self.label_random_mac.grid(column=1, row=0, rowspan=2)

        # BUTTON - RANDOM MAC
        self.null_label3 = Message(self.labelframe_random_mac, text="")
        self.null_label3.grid(column=2, row=0)
        self.button_random_mac = ttk.Button(self.labelframe_random_mac, text="Randomize MAC",
                                            command=self.randomize_mac)
        self.button_random_mac.grid(column=3, row=0)

        # LABELFRAME - RESTORE ORIGINAL
        self.null_label20 = Message(self.root, text="")
        self.null_label20.pack()
        self.labelframe_restore_original = LabelFrame(self.root, text="Restore original MAC")
        self.labelframe_restore_original.pack(fill="both", expand="no")

        # LABEL - RESTORE ORIGINAL
        self.null_label4 = Message(self.labelframe_restore_original, text="")
        self.null_label4.grid(column=0, row=0)
        self.label_restore_original = Label(self.labelframe_restore_original,
                                            text="Restores the original selected interface's\n MAC address")
        self.label_restore_original.grid(column=1, row=0)

        # BUTTON - RESTORE ORIGINAL
        self.null_label5 = Message(self.labelframe_restore_original, text="")
        self.null_label5.grid(column=2, row=0)
        self.button_restore_original = ttk.Button(self.labelframe_restore_original, text="Restore MAC",
                                                  command=self.restore_mac)
        self.button_restore_original.grid(column=3, row=0)

        # LABELFRAME - MAC SPOOFING
        self.null_label15 = Message(self.root, text="")
        self.null_label15.pack()
        self.labelframe_mac_spoofing = LabelFrame(self.root, text="MAC spoofing")
        self.labelframe_mac_spoofing.pack(fill="both", expand="no")

        # LABEL - MAC SPOOFING
        self.null_label16 = Message(self.labelframe_mac_spoofing, text="")
        self.null_label16.grid(column=0, row=0)
        self.label_mac_spoofing = Label(self.labelframe_mac_spoofing,
                                            text="Spoof client's MAC address during attack")
        self.label_mac_spoofing.grid(column=1, row=0)

        # CHECKBUTTON - MAC SPOOFING
        self.null_label17 = Message(self.labelframe_mac_spoofing, text="")
        self.null_label17.grid(column=2, row=0)
        self.macSpoofingVar = BooleanVar()
        self.checkbutton_mac_spoofing = ttk.Checkbutton(self.labelframe_mac_spoofing, text="Active",
                                                        variable=self.macSpoofingVar, command=self.mac_spoofing)
        self.checkbutton_mac_spoofing.grid(column=3, row=0)

        # BUTTON - DONE
        self.null_label14 = Message(self.root, text="")
        self.null_label14.pack()
        self.button_done = ttk.Button(self.root, text="Done", command= self.root.destroy)
        self.button_done.pack()

    def customize_mac(self):
        self.notify_view(0, self.entry_custom_mac.get())

    def randomize_mac(self):
        self.notify_view(1, "")

    def restore_mac(self):
        self.notify_view(2, "")

    def mac_spoofing(self):
        if self.macSpoofingVar.get():
            self.notify_view(3, True)
            print("--------------------------------------TRUE")
        else:
            self.notify_view(3, False)
            print("--------------------------------------FALSE")

    def notify_view(self, operation,value):
        """
        Operation values (int)
        0 - Custom mac
        1 - Random mac
        2 - Restore mac
        3 - Mac spoofing
        :param self:
        :param operation:
        :param value:
        :return:
        """
        self.main_view.get_notify_mac(operation, value)
