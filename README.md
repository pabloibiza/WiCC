WiCC
====
![](https://img.shields.io/github/license/pabloibiza/WiCC.svg)
![](https://img.shields.io/github/release/pabloibiza/WiCC.svg)
![](https://img.shields.io/github/release-date/pabloibiza/WiCC.svg)
![](https://img.shields.io/github/commits-since/pabloibiza/WiCC/v0.2.svg)
![](https://img.shields.io/github/contributors/pabloibiza/WiCC.svg)
![](https://img.shields.io/github/repo-size/pabloibiza/WiCC.svg)

<a href="url"><img src="https://github.com/pabloibiza/WiCC/blob/master/Resources/logo_circle_code.png" align="left" height="210" width="210" >
</a>

*WiFi Cracking Camp*

GUI tool for wireless WEP and WPA/WPA2 pentesting.
<br/><br/><br>
Developed by Pablo Sanz Alguacil, Miguel Yanes Fernández and Adam Chalkley, as the Group Project for 3rd year of the 
Bachelor of Science in Computing in Digital Forensics and Cyber Security at the **Technological University Dublin**.
<br/><br/><br/><br/>
**Tool under development. It is possible that some features have not yet been added.**

**Correct operation is not guaranteed.**
<br/><br/><br/>
Wireless pentesting tool with functionalities such as password cracking (in WEP and WPA/WPA2 networks), DoS attacks, 
client de-authentication, data decryption or fake base stations.
<br/><br/>

# Project insight

Tool developed in Python 3.7, developed and tested under Debian distributions (Ubuntu has also been tested). 
This tool is a frontend toolkit that integrates different open source tools for wireless pentesting. 
The utilised tools are the following:

* Aircrack-ng suite (including airdecap)
* ifconfig
* genpmk
* pyrit
* coWPAtty
* pgrep
* macchanger

# Requirements

You will need to run the program with root privileges, and using some version of python3. Also you need to have installed all of 
the tools mentioned in the section *Project insight*. In case you miss some of this requirements, 
you won't be able to initiate the tool.

Also, even not necessary, it is highly recommended to use a wireless card that supports both monitor mode and packet injection. 
In case your wireless card doesn't support them, you will be able to execute the attacks but may miss some advanced 
functionalities to, for example, speed-up the network cracking process.

# Usage

The tool is a framework utility, but you need to run it from the command line. To do so, you need to run with root privileges and
with Python 3+:

`$ sudo python3 WiCC.py [option(s)]`

There are also some advanced options that you can choose from the command line. This options are originaly meant for debugging
purposes, but you may find some of them useful:
* `-a` Auto-select the first available network interface.
* `-s` Avoid showing the splash image during startup.
* `-i` Ignore local save files.
* `-v` Select the verbose level for the output (default: 0, no output)

     * `-v`   Level 1 (basic output)
       
     * `-vv`  Level 2 (advanced output)
       
     * `-vvv` Level 3 (advanced output and executed commands)

You can always view the help with the option `--help`

# Source License
This project is under license GNU GPL 3.0


