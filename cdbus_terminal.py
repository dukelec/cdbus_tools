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
  --record [FILE]   # record the bus to a pcapng file, default: cdbus_<time>.pcapng in the
            | -r    #   current dir; open it in Wireshark with wireshark/cdbus.lua. Enter on
                    #   an empty line puts a mark into the recording, "# text" one with text
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
from datetime import datetime
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
from cdnet.utils.crc import modbus_crc
from cdnet.utils.pcapng import PcapngWriter, IF_CDBUS, IF_MARK, FLAG_INBOUND, FLAG_OUTBOUND
from cdnet.dev.cdbus_serial import CDBusSerial
from cdnet.dispatch import *

args = CdArgs()
dev_str = args.get("--dev", dft="ttyACM0")
baud = int(args.get("--baud", dft="115200"), 0)
rec_path = args.get("--record", "-r") # None: no recording, '': the default file name

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

# the recording holds the frames as they are on the wire, crc included; every packet is one
# write() to the file, so there is nothing to flush when the program ends
rec = None
if rec_path != None:
    rec_path = rec_path or datetime.now().strftime('cdbus_%Y%m%d_%H%M%S.pcapng')
    rec = PcapngWriter(rec_path, app='cdbus_terminal', dev_str=f'{dev_str} @ {baud}',
                       mark_str='marks: Enter on an empty line at the prompt of cdbus_terminal, or "# text"')
    print(f'recording to {rec_path}')

def with_crc(frame):
    return frame + modbus_crc(frame).to_bytes(2, byteorder='little')

def rx_echo():
    while True:
        ts, rx = dev.recv(with_ts=True) # ts: when the serial thread read it in
        if rec:
            rec.packet(IF_CDBUS, with_crc(rx), ts, FLAG_INBOUND)
        print('\r-> ' + rx.hex())
        print('\r  (' + re.sub(br'[^\x20-\x7e]',br'.', rx).decode() + ')\n<-', end='',  flush=True)

_thread.start_new_thread(rx_echo, ())

while True:
    sleep(0.1)
    tx = input("\r<- ")
    if not len(tx) or tx.startswith('#'): # a mark, as Enter in a Logs window of cdbus_gui; with text after the #
        if rec:
            text = tx[1:].strip()
            rec.packet(IF_MARK, text.encode(), comment=text)
        continue
    tx = bytes.fromhex(tx)
    if rec: # before the send, so the reply cannot land ahead of it in the file
        rec.packet(IF_CDBUS, with_crc(tx), flags=FLAG_OUTBOUND)
    err = dev.send(tx)
    if err and rec:
        rec.packet(IF_MARK, b'tx failed', comment=f'tx failed: {err}') # the frame above never went out

