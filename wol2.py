#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#

#!/usr/bin/python
from socket import socket, AF_INET, SOCK_DGRAM, SOL_SOCKET, SO_BROADCAST

data = '\xFF\xFF\xFF\xFF\xFF\xFF' + '\xAA\xAA\xAA\xAA\xAA\xAA' * 16

sock = socket(AF_INET, SOCK_DGRAM)
sock.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
sock.sendto(data, ('<broadcast>', 9))
sock.close()