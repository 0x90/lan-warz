import socket
from dpkt import ethernet,arp
import dpkt
import struct
import string
import sys
import signal


iface = "ath0"
mac   = "00:09:5B:98:0D:85"
inet  = "10.29.1.61"


debug = False


# this should be somewhere is dpkt ? 
ETH_ADDR_BROADCAST = '\xff\xff\xff\xff\xff\xff'
ETH_ADDR_UNSPEC = '\x00\x00\x00\x00\x00\x00'

def eth_ntoa(buffer):
    # Convert binary data into a string.
    macaddr = ''
    for intval in struct.unpack('BBBBBB', buffer):
        if intval > 15:
            replacestr = '0x'
        else:
            replacestr = 'x'
        macaddr = ''.join([macaddr, hex(intval).replace(replacestr, '')])
    return macaddr

def eth_aton(buffer):
    addr =''
    temp = string.split(buffer,':')
    buffer = string.join(temp,'')
    # Split up the hex values and pack.
    for i in range(0, len(buffer), 2):
        addr = ''.join([addr,struct.pack('B', int(buffer[i: i + 2], 16))],)
    return addr




def buildArp(addr):
    arp_p = arp.ARP()
    arp_p.sha = eth_aton(mac)          # sender hardware addr
    arp_p.spa = socket.inet_aton(inet) # sender ip addr
    arp_p.tha = ETH_ADDR_UNSPEC        # dest hardware addr 
    arp_p.tpa = socket.inet_aton(addr) # ip addr of request
    arp_p.op = arp.ARP_OP_REQUEST

    packet = ethernet.Ethernet()
    packet.src = eth_aton(mac)
    packet.dst = ETH_ADDR_BROADCAST
    packet.data = arp_p
    packet.type = ethernet.ETH_TYPE_ARP

    if debug: print dpkt.hexdump(str(packet))

    return packet



def quit(signum,frame):
    print "Scan ended.."
    sys.exit(0)

    
signal.alarm(2)
signal.signal(signal.SIGALRM,quit)


s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW)
s.bind((iface,ethernet.ETH_TYPE_ARP))



for i in range (1,255):
    addr = "10.29.1.%s" % i
    packet = buildArp(addr)
    s.send(str(packet))








print "Results..."
while 1:


    data = s.recv(1024)
    if debug: print dpkt.hexdump(data)
    sys.stdout.flush()



    answer = ethernet.Ethernet(data)
    arp_p = answer.data


    orig = socket.inet_ntoa( arp_p.spa )
    mac_add = eth_ntoa( arp_p.sha)
    dest = socket.inet_ntoa( arp_p.tpa )

    if debug:print dpkt.hexdump( str(arp_p) )

    if arp_p.op != arp.ARP_OP_REQUEST:
        if dest ==  inet:
            print "Anser:  %s is at %s"  % (orig,mac_add)
            
        else:
            print "Not for me.. Origin:%s Target:%s Answer:%s" % (orig, dest,mac_add)
    else:
        if debug:print "Host %s look for address of %s" % (orig,dest)
        
     



