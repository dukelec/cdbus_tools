#!/usr/bin/env python3
# Software License Agreement (MIT License)
#
# Copyright (c) 2017, DUKELEC, Inc.
# All rights reserved.
#
# Author: Duke Fong <d@d-l.io>

"""CDNET debug tool

Args:
  --dev DEV         # specify serial port, default: /dev/ttyACM0
  --baud BAUD       # set baudrate, default: 115200
  --mac MAC         # set CDBUS Bridge filter at first, default: 1
  --help    | -h    # this help message
  --verbose | -v    # debug level: verbose
  --debug   | -d    # debug level: debug
  --info    | -i    # debug level: info

Command prompt example:

$ ./cdnet_terminal.py --verbose --baud 0xcdcd
<- 
<- sock.sendto(b'', ('00:00:fe', 1))
cdnet.dev.serial: VERBOSE: <- 00 fe 02 40 01
cdnet.dev.serial: VERBOSE: -> ff 00 4a 01 40 4d 3a 20 63 64 62 75 73 20 62 72 69 64 67 65 3b 20 53 3a 20 31 65 30 30 34 31 30 30 30 34 35 30 34 64 34 64 33 35 33 31 33 32 32 30 3b 20 53 57 3a 20 76 35 2e 31 2d 33 30 2d 67 37 65 62 34 61 39 34
-> 4d3a206364627573206272696467653b20533a203165303034313030303435303464346433353331333232303b2053573a2076352e312d33302d67376562346139342d6469727479 ('00:00:ff', 1)
  (M: cdbus bridge; S: 1e00410004504d4d35313220; SW: v5.1-30-g7eb4a94)
<- 
"""

import sys, os
import struct
from time import sleep
import _thread
import re
try:
    import readline                     # history and line editing on linux / macos
except ImportError:
    try:
        from pyreadline3 import Readline   # windows: pip install pyreadline3
        readline = Readline()
    except ImportError:
        pass                            # input() works without, only no history

sys.path.append(os.path.join(os.path.dirname(__file__), './pycdnet'))

from cdnet.utils.log import *
from cdnet.utils.cd_args import CdArgs
from cdnet.dev.cdbus_serial import CDBusSerial
from cdnet.dispatch import *

args = CdArgs()
dev_str = args.get("--dev", dft="ttyACM0")
baud = int(args.get("--baud", dft="115200"), 0)
local_mac = int(args.get("--mac", dft="0x00"), 0)

if args.get("--help", "-h") != None:
    print(__doc__)
    exit()

if args.get("--verbose", "-v") != None:
    logger_init(logging.VERBOSE)
elif args.get("--debug", "-d") != None:
    logger_init(logging.DEBUG)
elif args.get("--info", "-i") != None:
    logger_init(logging.INFO)

dev = CDBusSerial(dev_str, baud=baud)

CDNetIntf(dev, mac=local_mac)
sock = CDNetSocket(('', 0x40))


def rx_echo():
    while True:
        rx = sock.recvfrom()
        print('\r-> ' + rx[0].hex(), rx[1])
        print('\r  (' + re.sub(br'[^\x20-\x7e]',br'.', rx[0]).decode() + ')\n<-', end='',  flush=True)

_thread.start_new_thread(rx_echo, ())

while True:
    sleep(0.1)
    cmd = input("\r<- ")
    if not len(cmd):
        continue
    exec(cmd)

