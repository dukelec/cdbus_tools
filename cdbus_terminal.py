#!/usr/bin/env python3
# Software License Agreement (BSD License)
#
# Copyright (c) 2017, DUKELEC, Inc.
# All rights reserved.
#
# Author: Duke Fong <duke@dukelec.com>


import sys, os
from time import sleep
import readline
import _thread
from argparse import ArgumentParser

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from cdbus_tools.comm.cdbus_serial import *
from cdbus_tools.utils.log import *

#logger_init(logging.VERBOSE)
logger_init(logging.DEBUG)
#logger_init(logging.INFO)

parser = ArgumentParser()
parser.add_argument('--mac', dest='local_mac', default=1)
parser.add_argument('--direct', action='store_true')
parser.add_argument('--dev', dest='dev', default='/dev/ttyACM0')
args = parser.parse_args()

cdbus_serial = CdbusSerial(dev_port=args.dev)

if not args.direct:
    print('cdbus_bridge get info:')
    cdbus_serial.tx(b'\xaa\x55\x01\x01')
    print(cdbus_serial.rx_queue.get()[4:])
    print()

    local_mac = int(args.local_mac)
    print('cdbus_bridge set filter %d:' % local_mac)
    cdbus_serial.tx(b'\xaa\x55\x04\x03\x08\x00' + local_mac.to_bytes(1, byteorder='little'))
    print('' + to_hexstr(cdbus_serial.rx_queue.get()) + '\n')

def rx_echo():
    while True:
        rx = cdbus_serial.rx_queue.get()
        if not args.direct:
            rx = rx[3:5] + (rx[2]-2).to_bytes(1, byteorder='little') + rx[5:]
        print('\r-> ' + to_hexstr(rx) + '\n<- ', end='',  flush=True)

_thread.start_new_thread(rx_echo, ())

while True:
    tx = input("<- ")
    if not len(tx):
        continue
    tx = bytes.fromhex(tx)
    if not args.direct:
        tx = b'\xaa\x56' + (tx[2]+2).to_bytes(1, byteorder='little') + tx[0:2] + tx[3:]
    cdbus_serial.tx(tx)
