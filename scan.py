#!/usr/bin/python
# -*- encoding: utf-8 -*-
#

__author__ = '090h'
__license__ = 'GPL'

import Queue
import threading
from scapy.all import *


class workerThread(threading.Thread):

    def __init__(self, queue, destIP, lock):
        threading.Thread.__init__(self)
        self.queue = queue
        self.destIP = destIP
        self.lock = lock

    def run(self):
        while True:
            self.lock.acquire()
            self.dport = self.queue.get()  # Grab the port not from the queue
            reply = sr1(IP(dst=self.destIP) / TCP(sport=RandShort(), dport=self.dport), verbose=0, timeout=1)
            if reply == "<type 'NoneType'>":
                print str(sport) + " is filtered"
            elif reply.haslayer(TCP) and reply.getlayer(TCP).flags == 0x12:
                print "Port open: " + str(reply.sport) + reply.sprintf(" %TCP.sport%")
                send_rst = sr(IP(dst=self.destIP) / TCP(dport=reply.sport, sport=RandShort(), flags="R"), verbose=0,
                              timeout=1)
            self.queue.task_done()
            self.lock.release()


if __name__ == '__main__':
    try:
        destIP = sys.argv[1]
        portRange = sys.argv[2].split("-")
        startPort = int(portRange[0])
        endPort = int(portRange[1])

        queue = Queue.Queue()

        # Fill the queue
        for q in range(startPort, endPort + 1):
            queue.put(q)


        #create the threads and pass them the queue
        for port in range(10):
            lock = threading.Lock()
            worker = workerThread(queue, destIP, lock)
            worker.setDaemon(True)
            print "Creating thread ", port + 1
            worker.start()

        #Wait for all queues to and threads to finish
        queue.join()
        print "\nScan complete\n"

    except:
        print "Usage: synScannerMultiThread <ip-address> <startport-endport>"