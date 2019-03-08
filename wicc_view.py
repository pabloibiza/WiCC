#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    WiCC (Wireless Cracking Camp)
    GUI tool for wireless cracking on WEP and WPA/WPA2 networks.
    Project developed by Pablo Sanz Alguacil and Miguel Yanes Fernández, as the Group Project for the 3rd year of the
    Bachelor of Sicence in Computing in Digital Forensics and CyberSecurity, at TU Dublin - Blanchardstown Campus
"""


class View:
    control = ""
    interfaces = ""
    networks = ""

    def __init__(self, control):
        self.control = control

    def get_notify(self, interfaces, networks):
        self.interfaces = interfaces
        self.networks = networks

    def send_notify(self, operation, value):
        self.control.get_notify(operation, value)
