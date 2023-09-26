#!/usr/bin/env python3
# Software License Agreement (MIT License)
#
# Copyright (c) 2018, DUKELEC, Inc.
# All rights reserved.
#
# Author: Duke Fong <d@d-l.io>

"""CDBUS IAP Tool

examples:

read config:
  ./cdbus_iap.py --out-file conf.bin --addr=0x0801F800 --size=30

write config:
  ./cdbus_iap.py --in-file conf.bin --addr=0x0801F800

read fw:
  ./cdbus_iap.py --out-file fw.bin --addr=0x0800c000 --size=xxx
  
write fw:
  ./cdbus_iap.py --in-file fw.bin --addr=0x0800c000
"""

R_conf_ver = 0x0002 # len: 2
R_conf_from = 0x0004 # len: 1
R_do_reboot = 0x0005 # len: 1
R_keep_in_bl = 0x0006 # len: 1
R_save_conf = 0x0007 # len: 1

import sys, os
import struct
import _thread
import re
from argparse import ArgumentParser
from pathlib import Path

sys.path.append(os.path.join(os.path.dirname(__file__), './pycdnet'))

from cdnet.utils.log import *
from cdnet.utils.cd_args import CdArgs
from cdnet.dev.cdbus_serial import CDBusSerial
from cdnet.dispatch import *

args = CdArgs()
local_mac = int(args.get("--local-mac", dft="0x00"), 0)
dev_str = args.get("--dev", dft="ttyACM0")
baud = int(args.get("--baud", dft="115200"), 0)
target_addr = args.get("--target-addr", dft="80:00:fe")

addr = int(args.get("--addr", dft="0x0800c000"), 0)
size = int(args.get("--size", dft="0"), 0)
in_file = args.get("--in-file")
out_file = args.get("--out-file")
reboot_flag = args.get("--reboot") != None

sub_size = 128

if args.get("--help", "-h") != None:
    print(__doc__)
    exit()

if not in_file and not out_file:
    print(__doc__)
    #exit()

if args.get("--verbose", "-v") != None:
    logger_init(logging.VERBOSE)
elif args.get("--debug", "-d") != None:
    logger_init(logging.DEBUG)
elif args.get("--info", "-i") != None:
    logger_init(logging.INFO)


dev = CDBusSerial(dev_str, baud=baud)
CDNetIntf(dev, mac=local_mac)
sock = CDNetSocket(('', 0xcdcd))
sock_dbg = CDNetSocket(('', 9))


def dbg_echo():
    while True:
        rx = sock_dbg.recvfrom()
        #print('\x1b[0;37m  ' + re.sub(br'[^\x20-\x7e]',br'.', rx[0][5:-1]).decode() + '\x1b[0m')
        print('\x1b[0;37m  ' + re.sub(br'[^\x20-\x7e]',br'.', rx[0]).decode() + '\x1b[0m')

_thread.start_new_thread(dbg_echo, ())


def csa_write(offset, dat):
    sock.sendto(b'\x20' + struct.pack("<H", offset) + dat, (target_addr, 5))
    ret, _ = sock.recvfrom(timeout=1)
    if ret == None or ret[0] != 0x80:
        print(f'csa_write error at: 0x{offset:x}: {dat.hex()}')
    return ret

def csa_read(offset, len_):
    sock.sendto(b'\x00' + struct.pack("<HB", offset, len_), (target_addr, 5))
    ret, _ = sock.recvfrom(timeout=1)
    if ret == None or ret[0] != 0x80:
        print(f'csa_write read at: 0x{offset:x}, len: {len_}')
    return ret


if out_file or in_file:
    ret = csa_write(R_keep_in_bl, bytes([1]))
    print('stay_in_bl ret: ' + ret.hex())


def _read_flash(addr, _len):
    sock.sendto(b'\x00' + struct.pack("<IB", addr, _len), (target_addr, 8))
    ret, _ = sock.recvfrom()
    print(('  %08x: ' % addr) + ret.hex())
    if ret[0] != 0x80 or len(ret[1:]) != _len:
        print('read flash error')
        exit(-1)
    return ret[1:]

def _write_flash(addr, dat):    
    print(('  %08x: ' % addr) + dat.hex())
    sock.sendto(b'\x20' + struct.pack("<I", addr) + dat, (target_addr, 8))
    ret, _ = sock.recvfrom()
    print('  write ret: ' + ret.hex())
    if ret != b'\x80':
        print('write flash error')
        exit(-1)

def _erase_flash(addr, _len):
    sock.sendto(b'\x2f' + struct.pack("<II", addr, _len), (target_addr, 8))
    ret, _ = sock.recvfrom()
    print('  erase ret: ' + ret.hex())
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
        wdat = dat[cur-addr:cur-addr+size]
        _write_flash(cur, wdat)
        rdat = _read_flash(cur, len(wdat))
        if rdat != wdat:
            print(f'rdat != wdat, @{cur:08x}')
            exit(-1)
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
    csa_write(R_do_reboot, bytes([1]))

print('done.')

