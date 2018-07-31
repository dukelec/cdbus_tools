#!/usr/bin/env python3
# Software License Agreement (BSD License)
#
# Copyright (c) 2018, DUKELEC, Inc.
# All rights reserved.
#
# Author: Duke Fong <duke@dukelec.com>

"""CDBUS IAP Tool

examples:

read config:
  ./cdbus_iap.py --out-file conf.bin --addr=0x0801F800 --size=30

write config:
  ./cdbus_iap.py --in-file conf.bin --addr=0x0801F800

read fw:
  ./cdbus_iap.py --out-file fw.bin --addr=0x08010000 --size=xxx
  
write fw:
  ./cdbus_iap.py --in-file fw.bin --addr=0x08010000
"""

import sys, os
import struct
from argparse import ArgumentParser
from pathlib import Path

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from cdbus_tools.comm.cdbus_serial import *
from cdbus_tools.utils.log import *

#logger_init(logging.VERBOSE)
logger_init(logging.DEBUG)
#logger_init(logging.INFO)

parser = ArgumentParser(usage=__doc__)
parser.add_argument('--dev', dest='dev', default='/dev/ttyACM0')
parser.add_argument('--not-direct', action='store_true')
parser.add_argument('--local-addr', dest='local_addr', default=1)
parser.add_argument('--target-addr', dest='target_addr', default=254)

parser.add_argument('--addr', dest='addr', default=0x08010000)
parser.add_argument('--size', dest='size', default=0)
parser.add_argument('--in-file', dest='in_file')
parser.add_argument('--out-file', dest='out_file')
parser.add_argument('--reboot', action='store_true')
args = parser.parse_args()

def _int(val):
    try:
        return int(val)
    except:
        return int(val, 16)

sub_size = 128
addr = _int(args.addr)
size = _int(args.size)

if args.not_direct:
    local_addr = _int(args.local_addr)
    target_addr = _int(args.target_addr)
else:
    local_addr = 0xaa
    target_addr = 0x55

cdbus_serial = CdbusSerial(dev_port=args.dev)

def _bytes(val):
    return val.to_bytes(1, byteorder='little')

def tx_wrapper(dat):
    if args.not_direct:
        dat = b'\xaa\x56' + _bytes(dat[2]+2) + dat[0:2] + dat[3:]
    cdbus_serial.tx(dat)

def rx_wrapper(timeout=None):
    try:
        dat = cdbus_serial.rx_queue.get(timeout=timeout)
        if args.not_direct:
            dat = dat[3:5] + _bytes(dat[2]-2) + dat[5:]
        if not cdbus_serial.rx_queue.empty():
            print('error: rx queue not empty')
            exit(-1)
        return dat
    except:
        return b''

def reboot():
    tx_wrapper(_bytes(local_addr) + _bytes(target_addr) + bytes([3, 0x80, 10, 0x00]))

def stay_in_bl():
    tx_wrapper(_bytes(local_addr) + _bytes(target_addr) + bytes([3, 0x80, 10, 0x02]))
    ret = rx_wrapper(timeout=1)
    print('stay_in_bl ret: ' + to_hexstr(ret))

print('cdbus_bridge get info:')
cdbus_serial.tx(b'\xaa\x55\x01\x01')
print(cdbus_serial.rx_queue.get()[4:])
print()
if args.not_direct:
    print('cdbus_bridge set filter %d:' % local_addr)
    cdbus_serial.tx(b'\xaa\x55\x04\x03\x08\x00' + _bytes(local_addr))
    print('' + to_hexstr(cdbus_serial.rx_queue.get()) + '\n')
    print()
    print('target %d get info:' % target_addr)
    tx_wrapper(_bytes(local_addr) + _bytes(target_addr) + b'\x01\x01')
    print(cdbus_serial.rx_queue.get()[4:])
stay_in_bl()

def _read_flash(addr, _len):
    tx_wrapper(_bytes(local_addr) + _bytes(target_addr) + \
            bytes([8, 0x80, 11, 0x00]) + struct.pack("<IB", addr, _len))
    ret = rx_wrapper()
    print(('  %08x: ' % addr) + to_hexstr(ret))
    if len(ret[5:]) != _len:
        print('read flash error')
        exit(-1)
    return ret[5:]

def _write_flash(addr, dat):    
    print(('  %08x: ' % addr) + to_hexstr(dat))
    tx_wrapper(_bytes(local_addr) + _bytes(target_addr) + \
            bytes([7+len(dat), 0x80, 11, 0x01]) + struct.pack("<I", addr) + dat)
    ret = rx_wrapper()
    print('  write ret: ' + to_hexstr(ret))
    if len(ret) != 5:
        print('write flash error')
        exit(-1)

def _erase_flash(addr, _len):
    tx_wrapper(_bytes(local_addr) + _bytes(target_addr) + \
            bytes([11, 0x80, 11, 0xff]) + struct.pack("<II", addr, _len))
    ret = rx_wrapper()
    print('  erase ret: ' + to_hexstr(ret))
    if len(ret) != 5:
        print('erase flash error')
        exit(-1)


def read_flash(addr, _len):
    cur = addr
    ret = b''
    while True:
        size = min(sub_size, _len-(cur-addr))
        if size == 0:
            break
        ret += _read_flash(cur, size)
        cur += size
    return ret

def write_flash(addr, dat):
    cur = addr
    ret = b''
    _erase_flash(addr, len(dat))
    while True:
        size = min(sub_size, len(dat)-(cur-addr))
        if size == 0:
            break
        _write_flash(cur, dat[cur-addr:cur-addr+size])
        cur += size


if args.out_file:
    print('read %d bytes @%08x to file' % (size, addr), args.out_file)
    ret = read_flash(addr, size)
    with open(args.out_file, 'wb') as f:
        f.write(ret)
elif args.in_file:
    with open(args.in_file, 'rb') as f:
        dat = f.read()
    print('write %d bytes @%08x from file' % (len(dat), addr), args.in_file)
    write_flash(addr, dat)
elif not args.reboot:
    print(__doc__)

if args.reboot:
    print('reboot...')
    reboot()

