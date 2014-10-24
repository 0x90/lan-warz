#!/usr/bin/env python
#
import socket
import dpkt
import sys

pcapReader = dpkt.pcap.Reader(file(sys.argv[1], "rb"))
for ts, data in pcapReader:
    ether = dpkt.ethernet.Ethernet(data)
    if ether.type != dpkt.ethernet.ETH_TYPE_IP: raise
    ip = ether.data
    src = socket.inet_ntoa(ip.src)
    dst = socket.inet_ntoa(ip.dst)
    print "%s -> %s" % (src, dst)