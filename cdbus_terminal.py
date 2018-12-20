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
from argparse import ArgumentParser

sys.path.append(os.path.join(os.path.dirname(__file__), './pycdnet'))

from cdnet.utils.log import *
from cdnet.dev.cdbus_serial import CDBusSerial, to_hexstr
from cdnet.dispatch import *

#logger_init(logging.VERBOSE)
logger_init(logging.DEBUG)
#logger_init(logging.INFO)

parser = ArgumentParser(usage=__doc__)
parser.add_argument('--mac', dest='local_mac', default=1)
parser.add_argument('--direct', action='store_true')
parser.add_argument('--dev', dest='dev', default='/dev/ttyACM0')
args = parser.parse_args()

cdbus_serial = CDBusSerial(dev_port=args.dev, remote_filter=[0x55, 0x56])


if not args.direct:
    print('cdbus_bridge get info:')
    frame = cdnet_l1.to_frame(('80:00:aa', 0xcdcd), ('80:00:55', 1), b'\x40', 0xaa)
    cdbus_serial.send(frame)
    frame = cdbus_serial.recv()
    src, dst, dat, _ = cdnet_l1.from_frame(frame)
    print(dat[1:])
    print()

    local_mac = int(args.local_mac)
    print('cdbus_bridge set filter %d:' % local_mac)
    dat = b'\x68\x00' + bytes([local_mac])
    frame = cdnet_l1.to_frame(('80:00:aa', 0xcdcd), ('80:00:55', 3), dat, 0xaa)
    cdbus_serial.send(frame)
    frame = cdbus_serial.recv()
    src, dst, dat, _ = cdnet_l1.from_frame(frame)
    print(dat)
    print()

def rx_echo():
    while True:
        rx = cdbus_serial.recv()
        if not args.direct:
            rx = rx[3:5] + bytes([(rx[2]-2)]) + rx[5:]
        print('\r-> ' + to_hexstr(rx) + '\n<- ', end='',  flush=True)

_thread.start_new_thread(rx_echo, ())

while True:
    tx = input("<- ")
    if not len(tx):
        continue
    tx = bytes.fromhex(tx)
    if not args.direct:
        tx = b'\xaa\x56' + bytes([tx[2]+2]) + tx[0:2] + tx[3:]
    cdbus_serial.send(tx)

