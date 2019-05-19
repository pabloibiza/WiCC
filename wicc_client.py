#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    WiCC (Wifi Cracking Camp)
    GUI tool for wireless pentesting on WEP and WPA/WPA2 networks.
    Project developed by Pablo Sanz Alguacil, Miguel Yanes Fernández and Adan Chalkley,
    as the Group Project for the 3rd year of the Bachelor of Sicence in Computing in Digital Forensics and CyberSecurity
    at TU Dublin - Blanchardstown Campus
"""


class Client:
    client_id = ""
    station_MAC = ""
    first_seen = ""
    last_seen = ""
    power = 0
    packets = 0
    bssid = ""
    probed_bssids = ""

    def __init__(self, id, station_MAC, first_seen, last_seen, power, packets, bssid, probed_bssids):
        self.client_id = id
        self.station_MAC = station_MAC
        self.first_seen = first_seen
        self.last_seen = last_seen
        self.power = power
        self.packets = packets
        self.bssid = bssid
        self.probed_bssids = probed_bssids

    def get_bssid(self):
        """
        Getter for the bssid parameter
        :return: bssid of the client

        :Author: Miguel Yanes Fernández
        """
        return self.bssid

    def get_mac(self):
        """
        Getter fro the MAC parameter
        :return: station mac of the client

        :Author: Miguel Yanes Fernández
        """
        return self.station_MAC

    def get_list(self):
        """
        Create and return a list of parameters
        :return: list of all class parameters

        :Author: Miguel Yanes Fernández
        """
        list = []
        list.append(self.client_id)
        list.append(self.station_MAC)
        list.append(self.first_seen)
        list.append(self.first_seen)
        list.append(self.last_seen)
        list.append(self.power)
        list.append(self.power)
        list.append(self.packets)
        list.append(self.bssid)
        list.append(self.probed_bssids)

        return list
