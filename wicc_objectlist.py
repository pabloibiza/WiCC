#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    WiCC (Wireless Cracking Camp)
    GUI tool for wireless cracking on WEP and WPA/WPA2 networks.
    Project developed by Pablo Sanz Alguacil and Miguel Yanes Fernández, as the Group Project for the 3rd year of the
    Bachelor of Sicence in Computing in Digital Forensics and CyberSecurity, at TU Dublin - Blanchardstown Campus
"""


class ObjectList:

    objects_list = []

    def add_object(self, object):
        if not self.is_on_the_list(object):
            self.objects_list.append(object)

    def is_on_the_list(self, object):
        for obj in self.objects_list:
            if obj == object:
                return True
        return False

    def get_list(self):
        return self.objects_list
