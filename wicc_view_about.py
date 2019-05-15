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
from tkinter import Tk, ttk, Frame, Button, Label, Entry, Text, Checkbutton, \
    Scale, Listbox, Menu, BOTH, RIGHT, RAISED, N, E, S, W, \
    HORIZONTAL, END, FALSE, IntVar, StringVar, messagebox, filedialog, LabelFrame

class About:

    def __init__(self):
        self.build_window()
        self.root.mainloop()

    def build_window(self):
        """
        Generates the window.

        :author: Pablo Sanz Alguacil
        """

        self.root = Toplevel()
        self.root.geometry('460x300')
        self.root.resizable(width=False, height=False)
        self.root.title('About')

        # LABEL - INFO
        self.label_info = Label(self.root, pady=15,
                                text="Developed by as the Group Project for 3rd year of the Bachelor "
                                     "\nof Science in Computing in Digital Forensics and Cyber Security "
                                     "\nat the Technological University Dublin."
                                     "\n")

        self.label_info.pack()

        self.button = Button(self.root, text="Github", command=self.open_link)
        self.button.pack()

        self.frame = Frame(self.root)
        self.frame.pack()

        photo = PhotoImage(file="Resources/icon_small.png")
        photo_label = Label(self.frame, image=photo)
        photo_label.image = photo
        photo_label.pack(side=LEFT)

        self.label_collaborators = Label(self.frame, text="\tPablo Sanz Alguacil (Code)"
                                     "\n\tMiguel Yanes Fernández (Code)"
                                     "\n\tAdam Chalkley (Research)")
        self.label_collaborators.pack(side=RIGHT)

    def open_link(event):
        url = "http://www.github.com/pabloibiza/WiCC"
        webbrowser.open_new_tab(url)
