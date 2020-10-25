#!/usr/bin/env python3
# Software License Agreement (BSD License)
#
# Copyright (c) 2017, DUKELEC, Inc.
# All rights reserved.
#
# Author: Duke Fong <duke@dukelec.com>

"""Low level CDBUS debug tool

This tool use CDBUS Bridge by default, communicate with any node on the RS485 bus.

If you want to communicate with CDBUS Bridge itself,
or other device use CDBUS protol through serial port,
use --direct flag then.

Args:
  --dev DEV         # specify serial port, default: /dev/ttyACM0
  --mac MAC         # set CDBUS Bridge filter at first, default: 1
  --direct          # see description above
  --help    | -h    # this help message
  --verbose | -v    # debug level: verbose
  --debug   | -d    # debug level: debug
  --info    | -i    # debug level: info


Command prompt example1, send cdbus frame to ourself through RS485 side:
(TODO: the sub command 0x40 of read info command will changed to 0x00)

$ ./cdbus_terminal.py --verbose
cdbus_bridge: DEBUG: read info ...
cdbus_serial: VERBOSE: <- aa 55 03 80 01 00
cdbus_serial: VERBOSE: -> 55 aa 44 82 01 80 4d 3a 20 63 64 62 75 73 20 62 72 69 64 67 65 3b 20 53 3a 20 30 33 66 66 35 64 35 30 65 34 35 35 32 33 35 33 39 35 36 35 30 32 33 34 3b 20 53 57 3a 20 76 32 2e 30 2d 33 2d 67 63 39 34 33 63 65 32
cdbus_bridge: DEBUG: info: b'M: cdbus bridge; S: 03ff5d50e455235395650234; SW: v2.0-3-gc943ce2'
<- 
<- 01 00 01 cd
cdbus_serial: VERBOSE: <- aa 56 03 01 00 cd
cdbus_serial: VERBOSE: -> 56 aa 03 01 00 cd
-> 01 00 01 cd
  (....)

Command prompt example2, send frame to cdbus_bridge 0x55 address:

$ ./cdbus_terminal.py --verbose --direct
<- aa 55 03 80 01 40
cdbus_serial: VERBOSE: <- aa 55 03 80 01 00
cdbus_serial: VERBOSE: -> 55 aa 44 82 01 80 4d 3a 20 63 64 62 75 73 20 62 72 69 64 67 65 3b 20 53 3a 20 30 33 66 66 35 64 35 30 65 34 35 35 32 33 35 33 39 35 36 35 30 32 33 34 3b 20 53 57 3a 20 76 32 2e 30 2d 33 2d 67 63 39 34 33 63 65 32
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
from cdnet.dev.cdbus_bridge import CDBusBridge
from cdnet.dispatch import *

args = CdArgs()
dev_str = args.get("--dev", dft="/dev/ttyACM0")
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
    dev = CDBusSerial(dev_port=dev_str)
else:
    dev = CDBusBridge(dev_port=dev_str, filter_=local_mac)

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

