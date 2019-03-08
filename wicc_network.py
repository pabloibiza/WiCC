#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    WiCC (Wireless Cracking Camp)
    GUI tool for wireless cracking on WEP and WPA/WPA2 networks.
    Project developed by Pablo Sanz Alguacil and Miguel Yanes Fernández, as the Group Project for the 3rd year of the
    Bachelor of Sicence in Computing in Digital Forensics and CyberSecurity, at TU Dublin - Blanchardstown Campus
"""

class Network:
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

    def __init__(self, id, bssid, first_seen, last_seen, channel, speed, privacy, cipher, authentication, power, beacons, ivs, lan_ip, essid, handshake, password):
        self.id = id
        self.bssid = bssid
        self.first_seen = first_seen
        self.last_seen = last_seen
        self.channel = channel
        self.speed = speed
        self.privacy = privacy
        self.cipher = cipher
        self.authentication = authentication
        self.power = power
        self.beacons = beacons
        self.ivs = ivs
        self.lan_ip = lan_ip
        self.essid = essid
        self.handshake = handshake
        self.password = password

    def __str__(self):
        output = ""
        output.__add__("ID: " + self.id)
        output.__add__(" BSSID: " + self.bssid)
        output.__add__(" First Seen: " + self.first_seen)
        output.__add__(" Last Seen: " + self.last_seen)
        output.__add__(" Channel: " + self.channel)
        output.__add__(" Speed: " + self.speed)
        output.__add__(" Privacy: " + self.privacy)
        output.__add__(" Cipher:" + self.cipher)
        output.__add__(" Authentication: " + self.authentication)
        output.__add__(" Power: " + self.power)
        output.__add__(" Beacons: " + self.beacons)
        output.__add__(" IVs: " + self.ivs)
        output.__add__(" LAN-IP: " + self.lan_ip)
        output.__add__(" ESSID: " + self.essid)
        output.__add__(" Handshake: " + self.handshake)
        output.__add__(" Password: " + self.password)
        return output

    def get_list(self):
        list = []
        list.append(self.id)
        list.append(self.bssid)
        list.append(self.first_seen)
        list.append(self.last_seen)
        list.append(self.channel)
        list.append(self.speed)
        list.append(self.privacy)
        list.append(self.cipher)
        list.append(self.authentication)
        list.append(self.power)
        list.append(self.beacons)
        list.append(self.ivs)
        list.append(self.lan_ip)
        list.append(self.essid)
        list.append(self.handshake)
        list.append(self.password)
        return list

    # getters and setters
