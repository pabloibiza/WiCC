#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    WiCC (Wireless Cracking Camp)
    GUI tool for wireless cracking on WEP and WPA/WPA2 networks.
    Project developed by Pablo Sanz Alguacil and Miguel Yanes Fernández, as the Group Project for the 3rd year of the
    Bachelor of Sicence in Computing in Digital Forensics and CyberSecurity, at TU Dublin - Blanchardstown Campus
"""

from wicc_view import View
from wicc_objectlist import ObjectList
from wicc_interface import Interface


class Model:
    # interfaces = ObjectList()
    networks = ""
    view = ""

    def __init__(self, control):
        self.view = ""
        self.view = View.__init__(control,control)

    def set_interfaces(self, interfaces):
        self.interfaces = interfaces

    def add_interface(self, name, address, type, power, channel):
        interface = Interface.__init__(name, address, type, power, channel)
        self.interfaces.addObject(interface)
        print("Added interface " + interface.get_name())

    def set_networks(self, networks):
        self.networks = networks

    def notify_view(self):
        self.view.notify(self.interfaces, self.networks)

