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

from wicc_view_right_click import rClicker


class GenerateWordlist:
    main_view = ""
    words = []
    files_location = ""

    def __init__(self, view):
        self.main_view = view

        self.root = Toplevel()
        self.root.protocol("WM_DELETE_WINDOW", self.destroy_window)
        self.root.geometry('440x540')

        self.root.resizable(width=False, height=False)
        self.root.title('WiCC - Generate Wordlist')

        self.build_window()
        self.reset_list()
        self.root.mainloop()

    def build_window(self):
        """
        Generates the window.

        :author: Pablo Sanz Alguacil
        """

        # LABELFRAME - INFO
        self.labelframe_info = LabelFrame(self.root, text="")
        self.labelframe_info.pack(fill="both", expand="no", pady=5)

        # LABEL - INFO
        self.label_info = Label(self.labelframe_info, pady=15,
                                text="In this window you can create your custom wordlist\n"
                                     "After generate the list don't forget to select it using\n"
                                     "\"Select wordlist\" button in the main window. Words\n"
                                     "must be separated by spaces")
        self.label_info.pack(side=TOP)

        # LABELFRAME - ADD WORDS
        self.labelframe_write_word = LabelFrame(self.root, text="Add words")
        self.labelframe_write_word.pack(fill="both", expand="no", pady=5)

        # LABEL - ADD WORDS
        self.label_write_words = Label(self.labelframe_write_word, text="Write words: ")
        self.label_write_words.pack(side=LEFT, padx=5, pady=10)

        # ENTRY - ADD WORDS
        self.entry_words = ttk.Entry(self.labelframe_write_word)
        self.entry_words.pack(side=LEFT, padx=5, pady=10)
        self.entry_words.bind('<Button-3>', rClicker, add='')

        # BUTTON - ADD WORDS
        self.button_add = Button(self.labelframe_write_word, text="Add", command=self.add_word)
        self.button_add.pack(side=RIGHT, padx=5, pady=10)

        # LABELFRMAE - LIST
        self.labelframe_list = LabelFrame(self.root, text="Key words")
        self.labelframe_list.pack(fill="both", expand="no", pady=5)

        # LISTBOX - WORDS
        self.list_scrollbar = Scrollbar(self.labelframe_list)
        self.listbox_words = Listbox(self.labelframe_list, width=20, height=12)
        self.list_scrollbar['command'] = self.listbox_words.yview
        self.listbox_words['yscroll'] = self.list_scrollbar.set
        self.list_scrollbar.pack(in_=self.labelframe_list, side=RIGHT, fill=Y, expand="no")
        self.listbox_words.pack(in_=self.labelframe_list, fill="both", expand="no")

        # LABELFRMAE - CONTROLS
        self.labelframe_controls = LabelFrame(self.root, text="Controls")
        self.labelframe_controls.pack(fill="both", expand="no", pady=5)

        # BUTTON - RESET LIST
        self.button_reset = Button(self.labelframe_controls, text="Reset list", command=self.reset_list)
        self.button_reset.grid(column=0, row=0, padx=5, pady=10)

        # BUTTON - LOCATION
        self.button_location = Button(self.labelframe_controls, text="Location", command=self.choose_location)
        self.button_location.grid(column=1, row=0, padx=5, pady=10)

        # BUTTON - GENERATE LIST
        self.button_generate = Button(self.labelframe_controls, text="Generate", command=self.generate_list)
        self.button_generate.grid(column=2, row=0, padx=5, pady=10)

    def add_word(self):
        """
        Adds the word/words to the words array, and refreshes the Listbox

        :author: Pablo Sanz Alguacil
        """

        new_words = self.entry_words.get().split(" ")
        for word in new_words:
            self.words.append(word)
        self.listbox_words.delete(0, END)
        self.listbox_words.insert(END, *self.words)
        self.entry_words.delete(0, 'end')

    def reset_list(self):
        """
        Deletes all elements in the words array and Listobx

        :author: Pablo Sanz Alguacil
        """

        self.words = []
        self.listbox_words.delete(0, END)

    def choose_location(self):
        """
        Shows a popup window to select a directory to choose save the lists generated. then sends the path to
        the main view.

        :author: Pablo Sanz Algucil
        """

        path = filedialog.askdirectory(title="Choose directory",
                                       initialdir="/home",
                                       mustexist=True)
        self.files_location = path
        self.main_view.get_notify_childs(4, self.files_location)

    def generate_list(self):
        """
        Sends the order and words array to the main view.

        :author: Pablo Sanz Alguacil
        """

        self.main_view.get_notify_childs(5, self.words)

    def destroy_window(self):
        """
        Enables all buttons in the main window and destroys this window.

        :author: Pablo Sanz Alguacil
        """

        self.main_view.disable_window(False)
        self.root.destroy()
