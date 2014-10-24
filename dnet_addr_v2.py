#!/usr/bin/env python
#	ARP Scanner beta 1
#	Geordie (aka themacuser/t3h/gm2)

import dnet
import sys
import socket
import time
import pcap
import string
import time
import struct
import thread
	
def getmac(theaddr):
	return dnet.arp().get(dnet.addr(theaddr))

def printUsage():
	print """Usage: %s <interface name> <address range> <scan range>;
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

if (len(sys.argv) > 4):
	printUsage()
	sys.exit()

scanrange = range(start,end+1)

try:
	interface = dnet.eth(ifname)
except:
	print "Error opening interface. You probably aren't running as root, or the interface doesn't exist."
	sys.exit()

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
	
def table(ip, mac, dumpall):
	global theTable
	if (dumpall == 0):
		try:
			asd = theTable[0]
		except NameError:
			theTable={}
			theTable[0] = 0
			theTable[len(theTable) + 1] = {}
			theTable[len(theTable)]['ip'] = ip
			theTable[len(theTable)]['mac'] = mac
		except KeyError:
			print "not done yet"
		else:
			theTable[len(theTable) + 1] = {}
			theTable[len(theTable)]['ip'] = ip
			theTable[len(theTable)]['mac'] = mac
	else:
		print "-------------------------------"
		for key in range(1, len(theTable)):
			print "%s at %s" % (dnet.eth_ntoa(theTable[key+1]['mac']),dnet.ip_ntoa(theTable[key+1]['ip']))
	
	
	
def extract_arp(frame):
	d={}
	d['dest_mac'] = frame[0:6]
	d['src_mac'] = frame[6:12]
	d['type'] = frame[12:14]
	d['proto'] = frame[14:16]
	d['hwtype'] = frame[16:18]
	d['hwsize'] = frame[18:19]
	d['protosize'] = frame[19:20]
	d['opcode'] = frame[20:22]
	d['sendermac'] = frame[22:28]
	d['senderip'] = frame[28:32]
	d['targetmac'] = frame[32:38]
	d['targetip'] = frame[38:42]
	return d
	
def parse_packet(pktlen, data, timestamp):
	if 1: #try:
		if (data[12:14] == '\x08\x06'): # is it an ARP frame?
			decode = extract_arp(data)
			#if(decode['opcode'] == '\x00\x01'): # too many messages!
			#		print "arp who-has %s tell %s" % (dnet.ip_ntoa(decode['targetip']),dnet.ip_ntoa(decode['senderip']))
			if(decode['opcode'] == '\x00\x02'):
				#print "\nARP %s is at %s" % (dnet.ip_ntoa(decode['senderip']) , dnet.eth_ntoa(decode['sendermac']))
				sys.stdout.write("!")
				sys.stdout.flush()
				table(decode['senderip'], decode['sendermac'], 0);
	#except:
	#	print "Error decoding packet, ignoring"
		
def startListening(device):
	p = pcap.pcapObject()
	net, mask = pcap.lookupnet(device)
	p.open_live(device, 1600, 1, 100)
	print "Scanning on %s" % device
	
	try:
		while 1:
			p.dispatch(1, parse_packet)
			time.sleep(0.001)
	except KeyboardInterrupt:
		print '%s' % sys.exc_type
		print 'shutting down'
		print '%d packets received, %d packets dropped, %d packets dropped by interface' % p.stats()

def startScanning(ifname, addr_range, start, end):
	print("Scanning network - press enter to stop listening for ARP:")

	for addr in scanrange:
		arp_request(addr_range + str(addr))
		if ((addr % 10) == 0):
			sys.stdout.write(".")
			sys.stdout.flush()
			
thread.start_new_thread(startListening,(ifname,))
thread.start_new_thread(startScanning,(ifname, addr_range, start, end))
time.sleep(1)
raw_input( "" )
table("","",1)

