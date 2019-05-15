#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
    WiCC (Wireless Cracking Camp)
    GUI tool for wireless cracking on WEP and WPA/WPA2 networks.
    Project developed by Pablo Sanz Alguacil and Miguel Yanes Fernández, as the Group Project for the 3rd year of the
    Bachelor of Sicence in Computing in Digital Forensics and CyberSecurity, at TU Dublin - Blanchardstown Campus
"""

from tkinter import messagebox


class PopUpWindow:

    def popup_info(self, subject, text):
        messagebox.showinfo(subject, text)

    def popup_warning(self, subject, text):
        messagebox.showwarning(subject, text)

    def popup_error(self, subject, text):
        messagebox.showerror(subject, text)

    def popup_yesno(self, subject, text):
        return messagebox.askyesno(subject, text)


