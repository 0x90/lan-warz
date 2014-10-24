#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#

__author__ = '090h'
__license__ = 'GPL'

from sys import argv, exit
from os import path, popen
import commands
from random import randint
import sqlite3

# import scapy silently
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
conf.verb = 0


def get_macs():
    return [get_if_hwaddr(i) for i in get_if_list()]


def get_mac(iface=None):
    if iface is None:
        my_macs = [get_if_hwaddr(i) for i in get_if_list()]
        for mac in my_macs:
            if mac != "00:00:00:00:00:00":
                return mac
    else:
        data = commands.getoutput("ifconfig " + iface)
        words = data.split()
        found = 0
        for x in words:
            # print x
            if found != 0:
                mac = x
                break
            if x == "HWaddr":
                found = 1
        if len(mac) == 0:
            mac = 'Mac not found'
        mac = mac[:17]
        return mac


def random_mac():
    mac = [0x00,
           randint(0x00, 0xff),
           randint(0x00, 0xff),
           randint(0x00, 0xff),
           randint(0x00, 0xff),
           randint(0x00, 0xff)]
    return ':'.join(map(lambda x: "%02x" % x, mac))


def search_mac(mac):
    import sys, urllib2
    url = "http://api.macvendors.com/"
    macOUI = mac[:7]
    response = urllib2.urlopen(url + macOUI).read()
    return response


def lookup_mac(mac):
    mac = mac.replace("-", "").replace(":", "").replace(" ", "").upper()
    conn = sqlite3.connect('oui.db')
    db = conn.cursor()
    db.execute("SELECT * FROM oui WHERE mac = '%s'" % mac)
    try:
        return db.fetchone()[1]
    except:
        db.close()
        conn.close()
        return None


############################### macchanger ##################
def change_mac(iface, mac):
    if path.isfile("/usr/local/bin/macchanger"):
        print("MAC Changer is installed, using it...")
        print("[+] Changing your MAC address to something totally random...")  # More statuses
        popen("macchanger --random " + iface)  # CHANGES MAC ADDRESS!!!!!!!
    else:
        print("MAC Changer is not installed, using ifconfig method!")
        print("[+] Changing your MAC address to something totally random...")  # More statuses
        popen("ifconfig " + iface + " hw ether " + random_mac())

# if __name__ == '__main__':
#     data = sys.argv[1]
#     print "INPUT :: ", data
#     data = data.replace("-", "").replace(":", "").replace(" ", "").upper()
#     mac = MacLookup()
#     for i in range(0, len(data) - 5):
#         mac_data = data[i:i + 6]
#         org = mac.find(mac_data)
#         if org is not None:
#             print mac_data, org

if __name__ == '__main__':
    pass