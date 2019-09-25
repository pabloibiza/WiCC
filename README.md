WiCC
====
![](https://img.shields.io/github/license/pabloibiza/WiCC.svg)
![](https://img.shields.io/github/release/pabloibiza/WiCC.svg)
![](https://img.shields.io/github/release-date/pabloibiza/WiCC.svg)
![](https://img.shields.io/github/commits-since/pabloibiza/WiCC/v0.2.svg)
![](https://img.shields.io/github/contributors/pabloibiza/WiCC.svg)
![](https://img.shields.io/github/repo-size/pabloibiza/WiCC.svg)

<a href="url"><img src="https://github.com/pabloibiza/WiCC/blob/master/resources/logo_circle_code.png" align="left" height="210" width="210" >
</a>
<br/>
*WiFi Cracking Camp*

GUI tool for wireless WEP and WPA/WPA2 pentesting.
<br/><br/>
Developed by Pablo Sanz Alguacil, Miguel Yanes Fernández and Adam Chalkley, as the Group Project for 3rd year of the 
Bachelor of Science in Computing in Digital Forensics and Cyber Security at the **Technological University Dublin**.

<br/><br/><br/>
Wireless pentesting tool with functionalities such as password cracking (in WEP and WPA/WPA2 networks), DoS attacks, 
client de-authentication,and data decryption.
<br/><br/>

# New version - WiCC 2

**The original WiCC project is no longer mantained**, as its new versions are developped and mantained at the repository [WiCC2](https://github.com/wicc2/WiCC2). WiCC 2 is the newest version with added functionalities and fixes, so please refer to that version for further updates.
<br/><br/>

# Project insight

Tool developed in Python 3.7, developed and tested under [**Kali Linux**](https://www.kali.org/) and [**Parrot OS**](https://www.parrotsec.org/) distributions.
This tool is a GUI toolkit that integrates different open source tools for wireless pentesting. 
The utilised tools are the following:

* [aircrack-ng suite](https://tools.kali.org/wireless-attacks/aircrack-ng) (including [airdecap-ng](https://tools.kali.org/wireless-attacks/aireplay-ng))
* [ifconfig](https://en.wikipedia.org/wiki/Ifconfig)
* [pyrit](https://github.com/JPaulMora/Pyrit)
* [coWPAtty](https://tools.kali.org/wireless-attacks/cowpatty)
* [crunch](https://tools.kali.org/password-attacks/crunch)
<br/><br/>

# Requirements

You will need to run the application with root privileges, and using some version of Python 3+. Also, you need to have installed *aircrack-ng suite* and *ifconfig*, the rest of the tools mentioned in the section *Project insight* are optional. If any of the mentioned tools is not installed, the application will ask you to automatically install it. Of course, as this is a wireless pentesting tool, you will need some wireless card to perform the scans/attacks. In case you miss some of these requirements, you won't be able to initiate the tool. 

Is recommendable to run it on **Kali Linux** or **Parrot OS** since both have the required tools preinstalled. Also it is highly recommended to use a wireless card that supports both monitor mode and packet injection. In case your wireless card doesn't support monitor mode, you won't be able to execute the attacks and scans.
<br/><br/>

# What is monitor mode?

Monitor mode, or RFMON (Radio Frequency MONitor) mode, allows a computer with a wireless network interface controller (WNIC) to monitor all traffic received on a wireless channel. Unlike promiscuous mode, which is also used for packet sniffing, monitor mode allows packets to be captured without having to associate with an access point or ad hoc network first. Monitor mode only applies to wireless networks, while promiscuous mode can be used on both wired and wireless networks. Monitor mode is one of the eight modes that 802.11 wireless cards can operate in: Master (acting as an access point), Managed (client, also known as station), Ad hoc, Repeater, Mesh, Wi-Fi Direct, TDLS and Monitor mode.

Usually the wireless adapter is unable to transmit in monitor mode and is restricted to a single wireless channel, though this is dependent on the wireless adapter's driver, its firmware, and features of its chipset. Also, in monitor mode the adapter does not check to see if the cyclic redundancy check (CRC) values are correct for packets captured, so some captured packets may be corrupted.

# Usage

The tool is a framework utility, but you need to run it from the command line. To do so, you need to run under root privileges and Python 3+:

> `$ sudo python3 WiCC.py [options]`

<br/><br/>
There are also some advanced options that you can choose from the command line. These options are originaly meant for debugging purposes, but you may find some of them useful:
* `-a` Auto-select the first available network interface.
* `-i` Ignore local save files.
* `-p` Only basic pop-ups mode.
* `-v` Select the verbose level for the output (default: 0, no output)

     * `-v`   Level 1 (basic output)
       
     * `-vv`  Level 2 (advanced output)
       
     * `-vvv` Level 3 (advanced output and executed commands)

You can always view the help with the option `--help` or `-h`
<br/><br/>
<br/><br/>
![attack_wpa_gif](https://media.giphy.com/media/ZBDcgn9nMvCZUGSJrf/giphy.gif)
<br/><br/>

# Final release
The version 1.0 includes password cracking (WEP and WPA/WPA2 networks), DoS attacks, client de-authentication, and data decryption funtionalities. From now on, the WiCC project is mantained in [a different repository](https://github.com/wicc2/WiCC2). Newer releases can be found there.<br/>
If you want to get in contact to notify us about some bugs you encountered, or about some feature you thing could be interesting to add, you can use the contact information showed on our GitHub profiles listed below.
<br/><br/>

# Authors

* **Miguel Yanes Fernández** - *Project Manager, back-end developer, and documentation* - Github: [MiguelYanes](https://github.com/MiguelYanes)
* **Pablo Sanz Alguacil** - *UX designer, front-end developer, and documentation* - Github: [pabloibiza](https://github.com/pabloibiza)
* **Adam Chalkley** - *Documentation and research* - [adamchalkley2019](https://github.com/adamchalkley2019)

See also the list of [contributors](https://github.com/pabloibiza/WiCC/contributors) who participated in this project.
<br/><br/>

# Source License
This project is under license GNU GPL 3.0
<br/><br/>
![](https://www.gnu.org/graphics/gplv3-with-text-136x68.png)


