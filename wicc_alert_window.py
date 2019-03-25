#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    WiCC (Wireless Cracking Camp)
    GUI tool for wireless cracking on WEP and WPA/WPA2 networks.
    Project developed by Pablo Sanz Alguacil and Miguel Yanes Fernández, as the Group Project for the 3rd year of the
    Bachelor of Sicence in Computing in Digital Forensics and CyberSecurity, at TU Dublin - Blanchardstown Campus
"""
from tkinter import *
from tkinter import Tk, Button, Label


class Alert:

    def __init__(self, message):
        self.message = message
        self.root = Tk()
        self.root.resizable(width=True, height=True)
        self.root.title('WiCC - Alert')
        self.alert_window()
        self.root.mainloop()

    def alert_window(self):
        label_message = Message(self.root, text=self.message)
        label_message.grid(row=0)

        search_button = Button(self.root, text='Accept', command=self.root.destroy)
        search_button.grid(row=1)

        null_label = Label(self.root, text="")
        null_label.grid(row=2)
