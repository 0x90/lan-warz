#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#

__author__ = '090h'
__license__ = 'GPL'

from sys import argv, exit
from os import path
from scapy.all import *

def arp_display(pkt):
    if pkt[ARP].op == 1: #who-has (request)
        return "Request: " + pkt[ARP].psrc + " is asking about " + pkt[ARP].pdst
    if pkt[ARP].op == 2: #is-at (response)
        return "*Response: " + pkt[ARP].hwsrc + " has address " + pkt[ARP].psrc

if __name__ == '__main__':
    # print sniff(filter="arp",count=10).summary()
    print(sniff(prn=arp_display, filter="arp", store=0, count=10))