#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#

# exec /usr/bin/python -x "$0" "$@"
#
node_lst = [
        'srv1 0a:1b:8c:0d:2e:7f',
        'srv2 0A-0B-4C-8D-CE:3F',
]
#
import os,sys,string,commands
import struct, socket
import re,random

retval = 0

mac_addr = "mac_addr.txt"
X = '([a-zA-Z0-9]{2}[:|\-|.]?){5}[a-zA-Z0-9]{2}'
S = re.compile(r'\s+')

mmap = {}

## First argument 'None' in str.translate is new in 2.6.
## Previously, it was a string of 256 characters
if sys.version_info < (2, 6):
    f1_arg = ''.join(chr(i) for i in xrange(256))
else:
    f1_arg = None

## broadcast address
sysOS = "uname -s"
BSD = "ifconfig | grep -w broadcast | cut -d\  -f 6"
LNX = "ip -o addr show | grep -w inet | grep -e eth | cut -d\  -f 9"
#
if commands.getoutput(sysOS) == "Linux":
    bCast = commands.getoutput(LNX)
elif commands.getoutput(sysOS) == "Darwin":
    bCast = commands.getoutput(BSD)
else:
    print "System not supported!!"
    sys.exit()

def WakeOnLan(mac_address):

    ## Building the Wake-On-LAN "Magic Packet"...
    ## Pad the synchronization stream.
    data = ''.join(['FFFFFFFFFFFF', mac_address * 20])
    msg = ''

    ## Split up the hex values and pack.
    for i in range(0, len(data), 2):
        msg = ''.join([msg, struct.pack('B', int(data[i: i + 2], 16))])

    ## ...and send it to the broadcast address using UDP
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.sendto(msg, (bCast, 9))
    s.close()

def sys_exit():
    sys.stdout.flush()
    sys.exit(1)

## check if hostname is provided
if len(sys.argv) != 2:
    print "Usage: %s <hostname>" % sys.argv[0]
    sys_exit()

for i in node_lst:
    # strip off everything from first "#" [if] found
    i = i.split('#',1)[0]
    if not re.search(X, i):
        continue

    h = S.split(i,1)[0]                 ## host name
    m = S.split(i,1)[-1]                ## MAC address
    mmap[h] = m.strip('\t|" "')

for j, k in mmap.iteritems():
    if sys.argv[1] == j:
        if not re.search(X.replace('zA-Z','fA-F'), k):
            print "Invalid MAC address [",k,"]; nothing to do!!"
            sys_exit()
        else:
            WakeOnLan(k.translate(f1_arg,':.-'))
            print "WOL request has been sent to %s [%s]" % (j,k)
            break
else:
    print "Host [%s] doesn't exist!!" % sys.argv[1]
    sys_exit()