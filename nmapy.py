#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#

__author__ = '090h'
__license__ = 'GPL'

# import scapy silently
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
conf.verb = 0

from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException


# nmap_proc = NmapProcess(targets="scanme.nmap.org", options="-sT")
# nmap_proc.run_background()
# while nmap_proc.is_running():
#     print("Nmap Scan running: ETC: {0} DONE: {1}%".format(nmap_proc.etc,
#                                                           nmap_proc.progress))
#     sleep(2)
#
# print("rc: {0} output: {1}".format(nmap_proc.rc, nmap_proc.summary))


# start a new nmap scan on localhost with some specific options
def do_scan(targets, options):
    parsed = None
    nmproc = NmapProcess(targets, options)
    rc = nmproc.run()
    if rc != 0:
        print("nmap scan failed: {0}".format(nmproc.stderr))
    # print(type(nmproc.stdout))

    try:
        parsed = NmapParser.parse(nmproc.stdout)
    except NmapParserException as e:
        print("Exception raised while parsing scan: {0}".format(e.msg))


    return parsed


# print scan results from a nmap report
def print_scan(nmap_report):
    for host in nmap_report.hosts:
        if len(host.hostnames):
            tmp_host = host.hostnames.pop()
        else:
            tmp_host = host.address

        print("Nmap scan report for {0} ({1})".format(
            tmp_host,
            host.address))
        print("Host is {0}.".format(host.status))
        print("  PORT     STATE         SERVICE")

        for serv in host.services:
            pserv = "{0:>5s}/{1:3s}  {2:12s}  {3}".format(
                    str(serv.port),
                    serv.protocol,
                    serv.state,
                    serv.service)
            if len(serv.banner):
                pserv += " ({0})".format(serv.banner)
            print(pserv)
    print(nmap_report.summary)

def search_ios_devices(iprange):
    nmap_report = do_scan(iprange, "-sV -p 62078")

    devices = []
    for host in filter(lambda host: host.status != 'down', nmap_report.hosts):
        tmp_host = host.hostnames.pop() if len(host.hostnames) else host.address

        for serv in host.services:
            if serv.state == 'open':
                devices.append(host.address)

            # pserv = "{0:>5s}/{1:3s}  {2:12s}  {3}".format(
            #         str(serv.port),
            #         serv.protocol,
            #         serv.state,
            #         serv.service)
            # if len(serv.banner):
            #     pserv += " ({0})".format(serv.banner)
            # print(tmp_host, pserv)
    return devices