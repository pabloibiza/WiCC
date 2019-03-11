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

    def __init__(self):
        return

    def add_object(self, object):
        """
        Adds a single object to the list
        :param object: object to add
        :return:
        """
        if not self.is_on_the_list(object):
            self.objects_list.append(object)

    def is_on_the_list(self, object):
        """
        Checks if an object already exists on the list
        :param object: object to check
        :return: true or false whether the object already exists or not
        """
        for obj in self.objects_list:
            if obj == object:
                return True
        return False

    def get_list(self):
        """
        Generates and returns a list of lists of parameters for every object on the class parameter list
        :return: list of lists of parameters
        """
        list = []
        for object in self.objects_list:
            list.append(object.get_list())
        return list
