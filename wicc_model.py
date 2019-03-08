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
from wicc_network import Network


class Model:
    interfaces = ObjectList()
    networks = ObjectList()
    view = ""

    def __init__(self, control):
        self.view = ""
        self.view = View(control)

    def set_interfaces(self, interfaces):
        self.interfaces = interfaces

    def add_interface(self, name, address, type, power, channel):
        interface = Interface(name, address, type, power, channel)
        self.interfaces.add_object(interface)
        print("Added interface " + interface.get_name())
        # self.notify_view()

    def set_networks(self, networks):
        """

        :param networks: list of lists of networks
        :return:
        """
        list_networks = ObjectList()

        first_time_empty = False

        for network in networks:
            id = ""
            bssid = ""
            first_seen = ""
            last_seen = ""
            channel = 0
            speed = 0
            privacy = ""
            cipher = ""
            authentication = ""
            power = 0
            beacons = 0
            ivs = 0
            lan_ip = ""
            essid = ""
            handshake = False
            password = ""

            cont = 0

            for pair in network:

                if cont == 0:
                    id = pair
                elif cont == 1:
                    bssid = pair
                elif cont == 2:
                    first_seen = pair
                elif cont == 3:
                    last_seen = pair
                elif cont == 4:
                    channel = pair
                elif cont == 5:
                    speed = pair
                elif cont == 6:
                    privacy = pair
                elif cont == 7:
                    cipher = pair
                elif cont == 8:
                    authentication = pair
                elif cont == 9:
                    power = pair
                elif cont == 10:
                    beacons = pair
                elif cont == 11:
                    ivs = pair
                elif cont == 12:
                    lan_ip = pair
                elif cont == 13:
                    essid = pair
                elif cont == 14:
                    handshake = pair
                elif cont == 15:
                    password = pair
                cont += 1

            if id == '':
                if first_time_empty:
                    print("break")
                    break
                first_time_empty = True
                print("first time true")
            elif id == 'BSSID':
                print("bssid and break")

            list_networks.add_object(Network(id, bssid, first_seen, last_seen, channel, speed, privacy, cipher,
                                             authentication, power, beacons, ivs, lan_ip, essid, handshake, password))
            print("Model: added network " + id + " " + essid)
        self.networks = list_networks
        # self.notify_view()

    def start_view(self):
        self.view.build_window()

    def notify_view(self):
        self.view.get_notify(self.interfaces.get_list(), self.networks.get_list())

