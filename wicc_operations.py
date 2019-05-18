#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    WiCC (Wifi Cracking Camp)
    GUI tool for wireless pentesting on WEP and WPA/WPA2 networks.
    Project developed by Pablo Sanz Alguacil, Miguel Yanes Fernández and Adan Chalkley,
    as the Group Project for the 3rd year of the Bachelor of Sicence in Computing in Digital Forensics and CyberSecurity
    at TU Dublin - Blanchardstown Campus
"""


class Operation:
    """
    Enumeration class for the operations used in the notifys between View and Control
    """
    SELECT_INTERFACE = "Select interface"
    SELECT_NETWORK = "Select network"
    ATTACK_NETWORK = "Attack network"
    STOP_SCAN = "Stop scan"
    STOP_RUNNING = "Stop running"
    RANDOMIZE_MAC = "Randomize mac"
    CUSTOMIZE_MAC = "Customize mac"
    RESTORE_MAC = "Restore mac"
    SPOOF_MAC = "Spoof mac"
    SELECT_CUSTOM_WORDLIST = "Select custom wordlist"
    SCAN_OPTIONS = "Scan Options"
    CHECK_MAC = "Check mac"
    PATH_GENERATED_LISTS = "Path generated lists"
    GENERATE_LIST = "Generate list"
    SELECT_TEMPORARY_FILES_LOCATION = "Select temporary files location"
    START_SCAN_WPA = "Start scan wpa"
    SILENT_SCAN = "Silent Scan"
    OPEN_CRACKED = "open cracked"
    DOS_ATTACK = "start dos attack"
    DECRYPT_FILE = "decrypt file"

