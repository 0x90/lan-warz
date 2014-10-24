#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#
#!/usr/bin/env python

__author__ = "Mohamed Assar < mohasr @ gmail . com >"
__version__ = "$Revision: 0.4 $"
__date__ = "$Date: 2007/02/25 15:37:19 $"
__copyright__ = "Copyright (c) 2007 Mohamed Assar"
__license__ = "GPL"

from threading import Timer
from os import getuid
from os import popen
from os import system

class ArpHealer:
    """Clear the arp table continously."""

    counter = 0
    timer = None
    import os
    currentOS = os.name
    del os # we don't need this module anymore

    def checkOS(self):
        if self.currentOS == 'posix':
        if getuid() != 0: # we must be root if we run on posix
        print "Error: You need to be root to use the this program "\
        "Try running it with either 'sudo' or 'su -e'"
        from os import sys
        sys.exit(1)
        else :
        self.arp = 'arp -n'
        else :
        self.arp = 'arp -a'

    def getArpTable(self):
        """Capture and returns the arp table for later processing."""

        arpTable = popen(self.arp).readlines()
        if len(arpTable) is 0:
        print "Error: no output from arp. Are you offline?"
        else:
        if self.currentOS == 'posix':
        del arpTable[0] # we don't need this line on linux
        else:
        del arpTable[0:3] # we don't need these lines on windows
        arpTable = [ "%s" %ip.split()[0] for ip in arpTable]
        print " - ".join(arpTable)
        return arpTable

    def arp_heal():
        """Deletes the arp table every 2 seconds"""

        self.counter+=1
        print '\n[', self.counter ,']'
        arpTable = self.getArpTable()
        for ip in arpTable:
            system( 'arp -d ' + ip )
            self.timer = Timer(2.0, self.start)
            self.timer.start()

        def start(self):
        """Starts the process"""

        self.arp_heal()

        def stop(self):
        """Stops the process"""
        self.timer.cancel()

if __name__ == '__main__':
    heal = ArpHealer()
    heal.checkOS()
    heal.start()