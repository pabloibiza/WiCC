#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    WiCC (Wireless Cracking Camp)
    GUI tool for wireless cracking on WEP and WPA/WPA2 networks.
    Project developed by Pablo Sanz Alguacil and Miguel Yanes Fernández, as the Group Project for the 3rd year of the
    Bachelor of Sicence in Computing in Digital Forensics and CyberSecurity, at TU Dublin - Blanchardstown Campus
"""

from wicc_interface import Interface
from wicc_network import Network
from wicc_client import Client


class Model:
    interfaces = []
    networks = []
    clients = []

    def __init__(self):
        """
        Class constructor. Initializes the list of interfaces and networks
        """
        self.interfaces = []
        self.networks = []

    def set_interfaces(self, interfaces):
        """
        Sets the list of interfaces as the one received as parameter
        :param interfaces: list of objects of the class Interface
        :return:
        """
        self.interfaces = interfaces

    def add_interface(self, name, address, type, power, channel):
        """
        Add a single interface given the parameters to create a new one
        :param name: string for the name of the interface
        :param address: string for the physical address of the interface
        :param type: string for the type of mode of the interface (managed, monitor, ...)
        :param power: int for the dBm of power of the interface
        :param channel: int for the selected channel
        :return:
        """
        interface = Interface(name, address, type, power, channel)
        if not self.interfaces.__contains__(interface):
            self.interfaces.append(interface)
        #self.interfaces.add_object(interface)

    def set_networks(self, networks):
        """
        Creates the new networks based on the list of parameters recevied
        :param networks: list of lists of network parameters
        :return:
        """
        list_networks = []

        first_time_empty = False
        id = 1

        for network in networks:
            # id = ""
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
            clients = 0

            cont = 0

            for pair in network:
                if cont == 0:
                    bssid = pair
                elif cont == 1:
                    first_seen = pair
                elif cont == 2:
                    last_seen = pair
                elif cont == 3:
                    channel = pair
                elif cont == 4:
                    speed = pair
                elif cont == 5:
                    privacy = pair
                elif cont == 6:
                    cipher = pair
                elif cont == 7:
                    authentication = pair
                elif cont == 8:
                    power = pair
                elif cont == 9:
                    beacons = pair
                elif cont == 10:
                    ivs = pair
                elif cont == 11:
                    lan_ip = pair
                elif cont == 13:
                    # parameter 12 shows the length of the essid, so it's not necessary
                    essid = pair
                # handshake and password aren't read from the interface list

                cont += 1

            if bssid == '':
                if first_time_empty:
                    break
                first_time_empty = True
            elif bssid != 'BSSID':
                list_networks.append(Network(id, bssid, first_seen, last_seen, channel, speed, privacy, cipher,
                                             authentication, power, beacons, ivs, lan_ip, essid, handshake,
                                             password, clients))
                id += 1
        self.networks = list_networks

    def set_clients(self, clients):
        """
        Given a list of parameters of clients, filters them and creates and store those clients
        :param clients: lists of lists of parameters of clients
        :return:
        """
        list_clients = []
        id = 1
        for client in clients:
            station_MAC = ""
            first_seen = ""
            last_seen = ""
            power = 0
            packets = 0
            bssid = ""
            probed_bssids = ""

            cont = 0
            for pair in client:
                if cont == 0:
                    station_MAC = pair
                elif cont == 1:
                    first_seen = pair
                elif cont == 2:
                    last_seen = pair
                elif cont == 3:
                    power = pair
                elif cont == 4:
                    packets = pair
                elif cont == 5:
                    bssid = pair
                    if bssid != ' (not associated) ':
                        self.add_client_network(bssid[1:])
                elif cont == 6:
                    probed_bssids = pair
                cont += 1

            list_clients.append(Client(id, station_MAC, first_seen, last_seen, power, packets, bssid, probed_bssids))
            id += 1

        self.clients = list_clients

    def add_client_network(self, bssid):
        """
        Add a client to the specified network. Searchs for the network and calls the method to add one client.
        :param bssid: bssid of the network
        :return:
        """
        for network in self.networks:
            if network.bssid == bssid:
                network.add_client()
                return

    def compare_interfaces(self, interfaces):
        """
        Compares a given list of interfaces with the local ones. Checks the names.
        :param interfaces: List of parameters of interfaces
        :return: boolean depending on whether both lists are equivalent
        """
        for interface in interfaces:
            for local_interface in self.interfaces:
                if str(interface[0]) == str(local_interface.get_name()):
                    return True
        return False

    def get_parameters(self):
        """
        Creates a list of parameters for both interfaces and networks.
        Will be used by the view to print these parameters
        :return: list of parameters of all interfaces, list of parameters of all networks
        """
        list_interfaces = []
        for object in self.interfaces:
            list_interfaces.append(object.get_list())
        list_networks = []
        for object in self.networks:
            list_networks.append(object.get_list())

        return list_interfaces, list_networks

    def search_network(self, network_id):
        for network in self.networks:
            if network.get_id() == network_id:
                return network
        return None
