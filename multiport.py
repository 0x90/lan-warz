#!/usr/bin/env python

"""
Copyright 2013 Interference Security
Contact : int3rf3r3nc3 [at] gmail [dot] com
Github  : https://github.com/interference-security/Multiport

Copyright 2014 Digital Security
Contact : okupreev@dsec.ru
Github  : https://github.com/0x90/Multiport

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
from sys import exit
from os import geteuid
from prettytable import PrettyTable
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
from socket import socket, AF_INET, SOCK_STREAM
import logging


if geteuid() != 0:
    print('Run as root please!')
    exit()

try:
    from scapy.all import *
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
except ImportError:
    print('Please install scapy:\n\tpip install scapy')
    exit()

class PortScan(object):

    @staticmethod
    def sock_scan(dst_ip, dst_port, dst_timeout):
        sock = socket(AF_INET, SOCK_STREAM)
        sock.settimeout(dst_timeout)
        try:
            sock.connect((dst_ip, dst_port))
            sock.close()
            return 'Open'
        except:
            return 'Closed'

    @staticmethod
    def tcp_connect_scan(dst_ip,dst_port,dst_timeout):
        src_port = RandShort()
        tcp_connect_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=dst_timeout)
        if(str(type(tcp_connect_scan_resp))=="<type 'NoneType'>"):
            return "Closed"
        elif(tcp_connect_scan_resp.haslayer(TCP)):
            if(tcp_connect_scan_resp.getlayer(TCP).flags == 0x12):
                send_rst = sr(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="AR"),timeout=dst_timeout)
                return "Open"
            elif (tcp_connect_scan_resp.getlayer(TCP).flags == 0x14):
                return "Closed"
        else:
            return "CHECK"

    @staticmethod
    def stealth_scan(dst_ip, dst_port, dst_timeout):
        src_port = RandShort()
        stealth_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=dst_timeout)
        if(str(type(stealth_scan_resp))=="<type 'NoneType'>"):
            return "Filtered"
        elif(stealth_scan_resp.haslayer(TCP)):
            if(stealth_scan_resp.getlayer(TCP).flags == 0x12):
                send_rst = sr(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="R"),timeout=dst_timeout)
                return "Open"
            elif (stealth_scan_resp.getlayer(TCP).flags == 0x14):
                return "Closed"
        elif(stealth_scan_resp.haslayer(ICMP)):
            if(int(stealth_scan_resp.getlayer(ICMP).type)==3 and int(stealth_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                return "Filtered"
        else:
            return "CHECK"

    @staticmethod
    def xmas_scan(dst_ip,dst_port,dst_timeout):
        xmas_scan_resp = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags="FPU"),timeout=dst_timeout)
        if (str(type(xmas_scan_resp))=="<type 'NoneType'>"):
            return "Open|Filtered"
        elif(xmas_scan_resp.haslayer(TCP)):
            if(xmas_scan_resp.getlayer(TCP).flags == 0x14):
                return "Closed"
        elif(xmas_scan_resp.haslayer(ICMP)):
            if(int(xmas_scan_resp.getlayer(ICMP).type)==3 and int(xmas_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                return "Filtered"
        else:
            return "CHECK"

    @staticmethod
    def fin_scan(dst_ip,dst_port,dst_timeout):
        fin_scan_resp = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags="F"),timeout=dst_timeout)
        if (str(type(fin_scan_resp))=="<type 'NoneType'>"):
            return "Open|Filtered"
        elif(fin_scan_resp.haslayer(TCP)):
            if(fin_scan_resp.getlayer(TCP).flags == 0x14):
                return "Closed"
        elif(fin_scan_resp.haslayer(ICMP)):
            if(int(fin_scan_resp.getlayer(ICMP).type)==3 and int(fin_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                return "Filtered"
        else:
            return "CHECK"

    @staticmethod
    def null_scan(dst_ip,dst_port,dst_timeout):
        null_scan_resp = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags=""),timeout=dst_timeout)
        if (str(type(null_scan_resp))=="<type 'NoneType'>"):
            return "Open|Filtered"
        elif(null_scan_resp.haslayer(TCP)):
            if(null_scan_resp.getlayer(TCP).flags == 0x14):
                return "Closed"
        elif(null_scan_resp.haslayer(ICMP)):
            if(int(null_scan_resp.getlayer(ICMP).type)==3 and int(null_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                return "Filtered"
        else:
            return "CHECK"

    @staticmethod
    def ack_flag_scan(dst_ip,dst_port,dst_timeout):
        ack_flag_scan_resp = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags="A"),timeout=dst_timeout)
        if (str(type(ack_flag_scan_resp))=="<type 'NoneType'>"):
            return "Stateful firewall present\n(Filtered)"
        elif(ack_flag_scan_resp.haslayer(TCP)):
            if(ack_flag_scan_resp.getlayer(TCP).flags == 0x4):
                return "No firewall\n(Unfiltered)"
        elif(ack_flag_scan_resp.haslayer(ICMP)):
            if(int(ack_flag_scan_resp.getlayer(ICMP).type)==3 and int(ack_flag_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                return "Stateful firewall present\n(Filtered)"
        else:
            return "CHECK"

    @staticmethod
    def window_scan(dst_ip,dst_port,dst_timeout):
        window_scan_resp = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags="A"),timeout=dst_timeout)
        if (str(type(window_scan_resp))=="<type 'NoneType'>"):
            return "No response"
        elif(window_scan_resp.haslayer(TCP)):
            if(window_scan_resp.getlayer(TCP).window == 0):
                return "Closed"
            elif(window_scan_resp.getlayer(TCP).window > 0):
                return "Open"
        else:
            return "CHECK"

    @staticmethod
    def udp_scan(dst_ip,dst_port,dst_timeout):
        udp_scan_resp = sr1(IP(dst=dst_ip)/UDP(dport=dst_port),timeout=dst_timeout)
        if (str(type(udp_scan_resp))=="<type 'NoneType'>"):
            retrans = []
            for count in range(0,3):
                retrans.append(sr1(IP(dst=dst_ip)/UDP(dport=dst_port),timeout=dst_timeout))
            for item in retrans:
                if (str(type(item))!="<type 'NoneType'>"):
                    udp_scan(dst_ip,dst_port,dst_timeout)
            return "Open|Filtered"
        elif (udp_scan_resp.haslayer(UDP)):
            return "Open"
        elif(udp_scan_resp.haslayer(ICMP)):
            if(int(udp_scan_resp.getlayer(ICMP).type)==3 and int(udp_scan_resp.getlayer(ICMP).code)==3):
                return "Closed"
            elif(int(udp_scan_resp.getlayer(ICMP).type)==3 and int(udp_scan_resp.getlayer(ICMP).code) in [1,2,9,10,13]):
                return "Filtered"
        else:
            return "CHECK"

    @staticmethod
    def table_scan(your_target,your_ports,your_timeout):
        x = PrettyTable(["Port No.","TCP Connect Scan","Stealth Scan","XMAS Scan","FIN Scan","NULL Scan", "ACK Flag Scan", "Window Scan", "UDP Scan"])
        x.align["Port No."] = "l"

        user_dst_ip = your_target
        port_list = your_ports
        user_dst_timeout = your_timeout

        print "[+] Target : %s\n" % user_dst_ip
        print "[*] Scan started\n"

        for i in port_list:
            tcp_connect_scan_res = PortScan.tcp_connect_scan(user_dst_ip,int(i),int(user_dst_timeout))
            stealth_scan_res = PortScan.stealth_scan(user_dst_ip,int(i),int(user_dst_timeout))
            xmas_scan_res = PortScan.xmas_scan(user_dst_ip,int(i),int(user_dst_timeout))
            fin_scan_res = PortScan.fin_scan(user_dst_ip,int(i),int(user_dst_timeout))
            null_scan_res = PortScan.null_scan(user_dst_ip,int(i),int(user_dst_timeout))
            ack_flag_scan_res = PortScan.ack_flag_scan(user_dst_ip,int(i),int(user_dst_timeout))
            window_scan_res = PortScan.window_scan(user_dst_ip,int(i),int(user_dst_timeout))
            udp_scan_res = PortScan.udp_scan(user_dst_ip,int(i),int(user_dst_timeout))
            x.add_row([i,tcp_connect_scan_res,stealth_scan_res,xmas_scan_res,fin_scan_res,null_scan_res,ack_flag_scan_res,window_scan_res,udp_scan_res])
        print x

        print "\n[*] Scan completed\n"


    @staticmethod
    def ports_from_range(text):
        parts = text.strip().split('-')
        s = int(parts[0])
        f = int(parts[1])

        if s < f:
            return [x for x in xrange(s, f)]
        else:
            return [x for x in xrange(f, s)]

    @staticmethod
    def port_from_string(text, sorted=False):
        ports = []

        for p in text.strip().split(','):
            if p.find('-') != -1:
                ports.extend(PortScan.ports_from_range(p))
            else:
                try:
                    port = int(p)
                    ports.append(port)
                except:
                    pass

        if sorted:
            ports.sort()

        return ports

banner = """

                 _ _   _                  _   
 _ __ ___  _   _| | |_(_)_ __   ___  _ __| |_ 
| '_ ` _ \| | | | | __| | '_ \ / _ \| '__| __|
| | | | | | |_| | | |_| | |_) | (_) | |  | |_ 
|_| |_| |_|\__,_|_|\__|_| .__/ \___/|_|   \__|
                        |_|    v1.1

Check the status of ports with all scans at once
by Interference Security


"""

if __name__ == "__main__":
    parser = ArgumentParser(description=banner, formatter_class=ArgumentDefaultsHelpFormatter)
    group = parser.add_argument_group('Scan types',)
    #group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-sT', '--tcp-scan', action='store_true', help='TCP scan')
    group.add_argument('-sU', '--udp-scan', action='store_true', help='UDP scap')
    group.add_argument('-sS', '--syn-scan', action='store_true', help='SYN scan')
    group.add_argument('-sA', '--ack-scan', action='store_true', help='ACK scan')
    group.add_argument('-sF', '--fin-scan', action='store_true', help='FIN scan')
    group.add_argument('-sN', '--null-scan', action='store_true', help='NULL scan')
    group.add_argument('-sW', '--window-scan', action='store_true', help='Window scan')
    group.add_argument('-sX', '--xmas-scan', action='store_true', help='XMAS scan')
    group.add_argument('-sP', '--scan-pretty', action='store_true', help='Scan all types and make output to pretty table')

    group = parser.add_argument_group('Misc options',)
    parser.add_argument("-t", "--timeout", type=int, default=2, help="Timeout value (default 2)")
    parser.add_argument("-T", "--threads", type=int, default=10, help="Thread count")
    parser.add_argument('-D', '--debug', action='store_true', help='Debug mode on')
    parser.add_argument('--version', action='version', version='%(prog)s 0.1')

    group = parser.add_argument_group('Target options',)
    parser.add_argument("-p", "--ports", metavar="",   help="Port list, range")
    parser.add_argument('hosts', metavar='', nargs='*', help='Hosts to scan')
    args = parser.parse_args()
    # target = args.target

    ports = PortScan.port_from_string(args.ports)
    print(ports)

    # TODO: Add support for network masks
    for host in args.hosts:
        PortScan.table_scan(host,ports,timeout)
    # ports = []
    # if args.pl:
    #         pl = (args.pl).split(",")
    #         ports += pl
    #
    # if args.pr:
    #         pr = (args.pr).split("-")
    #         pr.sort()
    #         pr_item1 = int(pr[0])
    #         pr_item2 = int(pr[1])+1
    #         new_pr = range(pr_item1,pr_item2,1)
    #         ports += new_pr
    #
    # timeout = int( args.t)
    #
    # if(not len(ports)>0):
    #         print "No ports specified.\nUse -h or --help to see the help menu"
    #         exit(0)
    #
    # ports = list(set(ports))
    # new_ports=[]
    # for item in ports:
    #         new_ports.append(int(item))
    # ports = new_ports
    # ports.sort()
