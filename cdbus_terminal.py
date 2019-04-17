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
  --dev DEV     # specify serial port, default: /dev/ttyACM0
  --mac MAC     # set CDBUS Bridge filter at first, default: 1
  --direct      # see description above
"""

import sys, os
from time import sleep
import readline
import _thread
import re

sys.path.append(os.path.join(os.path.dirname(__file__), './pycdnet'))

from cdnet.utils.log import *
from cdnet.utils.cd_args import CdArgs
from cdnet.dev.cdbus_serial import CDBusSerial, to_hexstr
from cdnet.dev.cdbus_bridge import CDBusBridge
from cdnet.dispatch import *

#logger_init(logging.VERBOSE)
#logger_init(logging.DEBUG)
#logger_init(logging.INFO)

args = CdArgs()
local_mac = int(args.get("--mac", dft="0"), 0)
dev_str = args.get("--dev", dft="/dev/ttyACM0")
direct = args.get("--direct") != None


if direct:
    dev = CDBusSerial(dev_port=dev_str)
else:
    dev = CDBusBridge(dev_port=dev_str, filter_=local_mac)

def rx_echo():
    while True:
        rx = dev.recv()
        print('\r-> ' + to_hexstr(rx))
        print('\r  (' + re.sub(br'[^\x20-\x7e]',br'.', rx).decode() + ')\n<-', end='',  flush=True)

_thread.start_new_thread(rx_echo, ())

while True:
    sleep(0.1)
    tx = input("\r<- ")
    if not len(tx):
        continue
    tx = bytes.fromhex(tx)
    dev.send(tx)

