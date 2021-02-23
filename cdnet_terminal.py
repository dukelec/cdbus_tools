#!/usr/bin/env python3
# Software License Agreement (BSD License)
#
# Copyright (c) 2017, DUKELEC, Inc.
# All rights reserved.
#
# Author: Duke Fong <duke@dukelec.com>

"""CDNET debug tool

This tool use CDBUS Bridge by default, communicate with any node on the RS485 bus.

If you want to communicate with CDBUS Bridge itself,
or other device use CDBUS protol through serial port,
use --direct flag then.

Args:
  --dev DEV         # specify serial port, default: /dev/ttyACM0
  --baud BAUD       # set baudrate, default: 115200
  --direct          # see description above
  --mac MAC         # set CDBUS Bridge filter at first, default: 1
  --help    | -h    # this help message
  --verbose | -v    # debug level: verbose
  --debug   | -d    # debug level: debug
  --info    | -i    # debug level: info

Command prompt example:

$ ./cdnet_terminal.py --verbose --direct
<- 
<- sock.sendto(b'\\x00', ('80:00:55', 1))
cdbus_serial: VERBOSE: <- aa 55 03 80 01 00
cdbus_serial: VERBOSE: -> 55 aa 44 82 01 80 4d 3a 20 63 64 62 75 73 20 62 72 69 64 67 65 3b 20 53 3a 20 30 33 66 66 35 64 35 30 65 34 35 35 32 33 35 33 39 35 36 35 30 32 33 34 3b 20 53 57 3a 20 76 32 2e 30 2d 33 2d 67 63 39 34 33 63 65 32
-> 80 4d 3a 20 63 64 62 75 73 20 62 72 69 64 67 65 3b 20 53 3a 20 30 33 66 66 35 64 35 30 65 34 35 35 32 33 35 33 39 35 36 35 30 32 33 34 3b 20 53 57 3a 20 76 32 2e 30 2d 33 2d 67 63 39 34 33 63 65 32 ('80:00:55', 1)
  (.M: cdbus bridge; S: 03ff5d50e455235395650234; SW: v2.0-3-gc943ce2)
<- 
"""

import sys, os
import struct
from time import sleep
import _thread
import re
try:
    import readline
except:
    from pyreadline import Readline
    readline = Readline()

sys.path.append(os.path.join(os.path.dirname(__file__), './pycdnet'))

from cdnet.utils.log import *
from cdnet.utils.cd_args import CdArgs
from cdnet.dev.cdbus_serial import CDBusSerial
from cdnet.dev.cdbus_bridge import CDBusBridge
from cdnet.dispatch import *

args = CdArgs()
dev_str = args.get("--dev", dft="ttyACM0")
baud = int(args.get("--baud", dft="115200"), 0)
direct = args.get("--direct") != None
local_mac = int(args.get("--mac", dft="0xaa" if direct else "0x00"), 0)

if args.get("--help", "-h") != None:
    print(__doc__)
    exit()

if args.get("--verbose", "-v") != None:
    logger_init(logging.VERBOSE)
elif args.get("--debug", "-d") != None:
    logger_init(logging.DEBUG)
elif args.get("--info", "-i") != None:
    logger_init(logging.INFO)


if direct:
    dev = CDBusSerial(dev_str, baud=baud)
else:
    dev = CDBusBridge(dev_str)
CDNetIntf(dev, mac=local_mac)
sock = CDNetSocket(('', 0xcdcd))


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

