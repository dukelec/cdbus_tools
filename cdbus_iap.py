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

sys.path.append(os.path.join(os.path.dirname(__file__), './pycdnet'))

from cdnet.utils.log import *
from cdnet.utils.cd_args import CdArgs
from cdnet.dev.cdbus_serial import CDBusSerial, to_hexstr
from cdnet.dev.cdbus_bridge import CDBusBridge
from cdnet.dispatch import *

#logger_init(logging.VERBOSE)
logger_init(logging.DEBUG)
#logger_init(logging.INFO)

args = CdArgs()
local_mac = int(args.get("--local-mac", dft="0"), 0)
dev_str = args.get("--dev", dft="/dev/ttyACM0")
direct = args.get("--direct") != None
target_addr = args.get("--target-addr", dft="80:00:01")

addr = int(args.get("--addr", dft="0x08010000"), 0)
size = int(args.get("--size", dft="0"), 0)
in_file = args.get("--in-file")
out_file = args.get("--out-file")
reboot_flag = args.get("--reboot") != None

sub_size = 128

if not in_file and not out_file:
    print(__doc__)
    exit()

if direct:
    dev = CDBusSerial(dev_port=dev_str)
else:
    dev = CDBusBridge(dev_port=dev_str, filter_=local_mac)
CDNetIntf(dev, mac=local_mac)
sock = CDNetSocket(('', 0xcdcd))


def reboot():
    sock.sendto(b'\x20', (target_addr, 10))

def stay_in_bl():
    sock.sendto(b'\x62', (target_addr, 10))
    ret, _ = sock.recvfrom(timeout=1)
    print('stay_in_bl ret: ' + to_hexstr(ret))

stay_in_bl()


def _read_flash(addr, _len):
    sock.sendto(b'\x40' + struct.pack("<IB", addr, _len), (target_addr, 11))
    ret, _ = sock.recvfrom()
    print(('  %08x: ' % addr) + to_hexstr(ret))
    if ret[0] != 0x80 or len(ret[1:]) != _len:
        print('read flash error')
        exit(-1)
    return ret[1:]

def _write_flash(addr, dat):    
    print(('  %08x: ' % addr) + to_hexstr(dat))
    sock.sendto(b'\x61' + struct.pack("<I", addr) + dat, (target_addr, 11))
    ret, _ = sock.recvfrom()
    print('  write ret: ' + to_hexstr(ret))
    if ret != b'\x80':
        print('write flash error')
        exit(-1)

def _erase_flash(addr, _len):
    sock.sendto(b'\x6f' + struct.pack("<II", addr, _len), (target_addr, 11))
    ret, _ = sock.recvfrom()
    print('  erase ret: ' + to_hexstr(ret))
    if ret != b'\x80':
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


if out_file:
    print('read %d bytes @%08x to file' % (size, addr), out_file)
    ret = read_flash(addr, size)
    with open(out_file, 'wb') as f:
        f.write(ret)
elif in_file:
    with open(in_file, 'rb') as f:
        dat = f.read()
    print('write %d bytes @%08x from file' % (len(dat), addr), in_file)
    write_flash(addr, dat)

if reboot_flag:
    print('reboot...')
    reboot()

