#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#

__author__ = '090h'
__license__ = 'GPL'

from sys import argv, exit
from os import path
from datetime import datetime, timedelta

from scapy.all import *
import matplotlib.pyplot as plt
import numpy as np


class PacketStat(object):

    def __init__(self, pcap):
        self.packets = rdpcap(pcap)
        self.stat = dict()

    def select(self, min=None, max=None):
        if min is None and max is None:
            return self.packets
        else:
            skipped = 0
            out = []
            for x in xrange(0, len(self.packets)):
                l = len(self.packets[x])

                if min is not None and l < min:
                    skipped += 1
                    continue

                if max is not None and l > max:
                    skipped += 1
                    continue

                out.append(self.packets[x])

        return out

    def parse(self):
        min = 1024
        max = 1
        self.stat['Total packets'] = len(self.packets)
        for x in xrange(0, len(self.packets)):
            dt = datetime.fromtimestamp(self.packets[x].time)
            print(dt)
            #dt.replace(minutes=dt.minutes, seconds=dt.seconds, microseconds=0)
            #dt -= timedelta(seconds=dt.seconds)
            #dt.replace(minutes=dt.minutes-(dt.minutes%10), dt.seconds=0, microseconds=0)
            #dt.replace(microseconds=0)
            #round_dt_to_seconds(dt)
            #dt.microsecond = 0
            #raw_input()

            l = len(self.packets[x])
            if l > max: max = l
            elif l < min: min = l


        self.stat['Min packet size'] = min
        self.stat['Max packet size'] = max


    def print_stat(self):
        for key in self.stat.keys():
            print('%s: %s' % (key, self.stat[key]))



if __name__ == '__main__':
    ps = PacketStat("/Users/090h/Downloads/task.pcap")
    ps.parse()
    ps.print_stat()