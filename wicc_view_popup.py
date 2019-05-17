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

    @staticmethod
    def info(subject, text):
        messagebox.showinfo(subject, text)

    @staticmethod
    def warning(subject, text):
        messagebox.showwarning(subject, text)

    @staticmethod
    def error(subject, text):
        messagebox.showerror(subject, text)

    @staticmethod
    def yesno(subject, text):
        return messagebox.askyesno(subject, text)

    @staticmethod
    def okcancel(subject, text):
        return messagebox.askokcancel(subject, text)


