#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    WiCC (Wifi Cracking Camp)
    GUI tool for wireless pentesting on WEP and WPA/WPA2 networks.
    Project developed by Pablo Sanz Alguacil, Miguel Yanes Fernández and Adan Chalkley,
    as the Group Project for the 3rd year of the Bachelor of Sicence in Computing in Digital Forensics and CyberSecurity
    at TU Dublin - Blanchardstown Campus
"""
import webbrowser
from tkinter import *
from tkinter import ttk, Frame, Button, Label
from wicc_view_popup import PopUpWindow


class DoS:
    logo = "resources/icon_medium.png"
    main_view = ""

    def __init__(self, main_view):
        self.main_view = main_view
        self.build_window()
        self.root.mainloop()

    def build_window(self):
        """
        Generates the window.

        :author: Pablo Sanz Alguacil
        """

        self.root = Toplevel()
        self.root.geometry('310x200')
        self.root.resizable(width=False, height=False)
        self.root.title('DoS Attack')
        self.root.protocol("WM_DELETE_WINDOW", self.destroy_window)

        self.labelframe_info = LabelFrame(self.root)
        self.labelframe_info.pack(fill="both", expand="no", pady=15)

        self.label_info = Label(self.labelframe_info, pady=15, text="With this tool yo can perform a DoS Attack."
                                                "\n\nIntroduce the attack's duration in seconds."
                                                "\nWait until the tool finishes the attack. ")
        self.label_info.pack()

        self.labelframe_buttons = LabelFrame(self.root)
        self.labelframe_buttons.pack(fill="both", expand="no", pady=5)

        self.label_time = Label(self.labelframe_buttons, text="Time: ")
        self.label_time.grid(column=0, row=0, padx=5, pady=5)

        self.entry = ttk.Entry(self.labelframe_buttons)
        self.entry.grid(column=1, row=0, padx=5, pady=5)

        self.button_start = Button(self.labelframe_buttons, text="Start", command=self.start_dos)
        self.button_start.grid(column=2, row=0, padx=5, pady=5)

    def start_dos(self):
        """
        Sends an order to the main view to start the DoS attack with a desired time. The packets are sended in groups
        of five, so the seconds introduced must be divided by 5.
        :param seconds: attacks duration

        :author: Pablo Sanz Alguacil
        """

        try:
            seconds = int(self.entry.get())
            converted_time = str(int(seconds / 5))
            int(self.entry.get())
            self.main_view.get_notify_childs(6, converted_time)

        except:
            PopUpWindow.warning("Warning", "Please introduce a valid number")

    def destroy_window(self):
        """
        Enables all buttons in the main window and destroys this window.

        :author: Pablo Sanz Alguacil
        """

        self.main_view.disable_window(False)
        self.root.destroy()




