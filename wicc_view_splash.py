#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    WiCC (Wireless Cracking Camp)
    GUI tool for wireless cracking on WEP and WPA/WPA2 networks.
    Project developed by Pablo Sanz Alguacil and Miguel Yanes Fernández, as the Group Project for the 3rd year of the
    Bachelor of Sicence in Computing in Digital Forensics and CyberSecurity, at TU Dublin - Blanchardstown Campus
"""
import tkinter as tk

class Splash:
    image_file = "Resources/splash.png"
    width = 600
    height = 400


    def __init__(self):
        root = tk.Tk()
        # show no frame
        root.overrideredirect(True)

        # get screen width and height
        ws = root.winfo_screenwidth()
        hs = root.winfo_screenheight()
        # calculate position x, y
        x = (ws / 2) - (self.width / 2)
        y = (hs / 2) - (self.height / 2)
        root.geometry('%dx%d+%d+%d' % (self.width, self.height, x, y))


        image = tk.PhotoImage(file=self.image_file)
        canvas = tk.Canvas(root, height=self.height, width=self.width, bg="brown")
        canvas.create_image(self.width/2, self.height/2, image=image)
        canvas.pack()

        root.after(2500, root.destroy)
        root.mainloop()