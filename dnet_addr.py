#!/usr/bin/env python
#	ARP Scanner beta 1
#	Geordie (aka themacuser/t3h/gm2)

import dnet
import sys
import socket
import time
	
def getmac(theaddr):
	return dnet.arp().get(dnet.addr(theaddr))

def printUsage():
	print """Usage: %s <interface name> <address range> <scan range>
Example: %s en1 192.168.0. 0-255""" % (sys.argv[0], sys.argv[0])

try:
	ifname = sys.argv[1]
	addr_range = sys.argv[2]
	host_range = sys.argv[3]
	addr = host_range.split("-", 2)
	start = int(addr[0])
	end = int(addr[1])
except:
	printUsage()
	sys.exit()

if ((start > 255 or end > 255) or (start < 0 or end < 0) or end < start):
	printUsage()
	sys.exit()

scanrange = range(start,end+1)

try:
	interface = dnet.eth(ifname)
except:
	print "Error opening interface. You probably aren't running as root, or the interface doesn't exist."

def ip_header(dst,src,type):
	packet = dst + src + str(type)
	return packet

def arp_header(hdr,op,sha,spa,tha,tpa):
	packet = hdr + op + sha + spa + tha + tpa
	return packet

def arp_request(ipaddr):
	sha_str = str(dnet.intf().get(ifname)['link_addr'])
	sha = dnet.eth_aton(sha_str)
	spa_str = str(dnet.intf().get(ifname)['addr']).split("/")[0]
	spa = dnet.ip_aton(spa_str)
	tha = dnet.ETH_ADDR_BROADCAST
	tpa = dnet.ip_aton(ipaddr)
	pkt = ip_header(tha,sha,'\x08\x06') 
	pkt += arp_header('\x00\x01\x08\x00\x06\x04','\x00\x01', sha, spa, '\x00\x00\x00\x00\x00\x00', tpa)
	interface.send(pkt)

print("Sending ARP Requests:")

for addr in scanrange:
	arp_request(addr_range + str(addr))
	if ((addr % 10) == 0):
		sys.stdout.write(".")
		sys.stdout.flush()
	
print ("\nWaiting for replies:")	

waitrange = range(5)
for wait in waitrange:
	sys.stdout.write(".")
	sys.stdout.flush()
	time.sleep(0.2)
	
print("\nQuerying ARP table:")

for addr in scanrange:
	result = getmac(addr_range + str(addr))
	if result:
		print "%s @ %s" % (result, addr_range + str(addr))