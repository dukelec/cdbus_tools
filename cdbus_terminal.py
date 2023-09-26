#!/usr/bin/env python3
# Software License Agreement (MIT License)
#
# Copyright (c) 2017, DUKELEC, Inc.
# All rights reserved.
#
# Author: Duke Fong <d@d-l.io>

"""Low level CDBUS debug tool

Args:
  --dev DEV         # specify serial port, default: ttyACM0
  --baud BAUD       # set baudrate, default: 115200
  --help    | -h    # this help message
  --verbose | -v    # debug level: verbose
  --debug   | -d    # debug level: debug
  --info    | -i    # debug level: info


Command prompt example1, send cdbus frame to ourself through RS485 side:

$ ./cdbus_terminal.py --verbose
<-
<- 01 00 01 cd
cdbus_serial: VERBOSE: <- 01 00 01 cd
cdbus_serial: VERBOSE: -> 01 00 01 cd
-> 01 00 01 cd
  (....)

Command prompt example2, send frame to cdbus_bridge 0x55 address:

$ ./cdbus_terminal.py --verbose --baud 0xcdcd
<-
<- 00 fe 03 80 01 00
cdbus_serial: VERBOSE: <- 00 fe 03 80 01 00
cdbus_serial: VERBOSE: -> fe 00 44 82 01 80 4d 3a 20 63 64 62 75 73 20 62 72 69 64 67 65 3b 20 53 3a 20 30 33 66 66 35 64 35 30 65 34 35 35 32 33 35 33 39 35 36 35 30 32 33 34 3b 20 53 57 3a 20 76 32 2e 30 2d 33 2d 67 63 39 34 33 63 65 32
-> 55 aa 44 82 01 80 4d 3a 20 63 64 62 75 73 20 62 72 69 64 67 65 3b 20 53 3a 20 30 33 66 66 35 64 35 30 65 34 35 35 32 33 35 33 39 35 36 35 30 32 33 34 3b 20 53 57 3a 20 76 32 2e 30 2d 33 2d 67 63 39 34 33 63 65 32
  (U.D...M: cdbus bridge; S: 03ff5d50e455235395650234; SW: v2.0-3-gc943ce2)
"""

import sys, os
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
from cdnet.dispatch import *

args = CdArgs()
dev_str = args.get("--dev", dft="ttyACM0")
baud = int(args.get("--baud", dft="115200"), 0)

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

def rx_echo():
    while True:
        rx = dev.recv()
        print('\r-> ' + rx.hex())
        print('\r  (' + re.sub(br'[^\x20-\x7e]',br'.', rx).decode() + ')\n<-', end='',  flush=True)

_thread.start_new_thread(rx_echo, ())

while True:
    sleep(0.1)
    tx = input("\r<- ")
    if not len(tx):
        continue
    tx = bytes.fromhex(tx)
    dev.send(tx)

