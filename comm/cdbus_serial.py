#!/usr/bin/env python3
# Software License Agreement (BSD License)
#
# Copyright (c) 2017, DUKELEC, Inc.
# All rights reserved.
#
# Author: Duke Fong <duke@dukelec.com>

# pip3.6 install pycrc --user
from PyCRC.CRC16 import CRC16

import threading
import queue
import serial
from ..utils.select_serial_port import select_port
from ..utils.log import *


def modbus_crc(data):
    return CRC16(modbus_flag=True).calculate(data)

def to_hexstr(data):
    return ' '.join('%02x' % b for b in data)


class CdbusSerial(threading.Thread):
    def __init__(self, name='cdbus_serial', dev_port=None, baud=115200, filters=None):
        
        self.rx_queue = queue.Queue(100)
        
        self.local_filter = [b'\xaa']
        self.remote_filter = [b'\x55', b'\x56']
        
        self.rx_bytes = b''
        self.logger = logging.getLogger(name)
        
        dev_port = select_port(logger=self.logger, dev_port=dev_port, filters=filters)
        if not dev_port:
            quit(1)
        
        # TODO: maintain serial connection by service callback
        self.com = serial.Serial(port=dev_port, baudrate=baud, timeout=0.5)
        if not self.com.isOpen():
            raise Exception('serial open failed')
        threading.Thread.__init__(self)
        self.daemon = True
        self.alive = True
        self.start()
    
    def run(self):
        while self.alive:
            bchar = self.com.read()
            if len(bchar) == 0:
                if len(self.rx_bytes) != 0:
                    self.logger.warning('drop: ' + to_hexstr(self.rx_bytes))
                    self.rx_bytes = b''
                continue
            
            self.rx_bytes += bchar
            #self.logger.log(logging.VERBOSE, '>>> ' + to_hexstr(bchar))
            
            if len(self.rx_bytes) == 1:
                if bchar not in self.remote_filter:
                    self.logger.debug('byte0 filtered: ' + to_hexstr(bchar))
                    self.rx_bytes = b''
            elif len(self.rx_bytes) == 2:
                if bchar not in self.local_filter:
                    self.logger.debug('byte1 filtered: ' + to_hexstr(bchar))
                    self.rx_bytes = b''
            elif len(self.rx_bytes) == self.rx_bytes[2] + 5:
                if modbus_crc(self.rx_bytes) != 0:
                    self.logger.debug('crc error: ' + to_hexstr(self.rx_bytes))
                else:
                    self.logger.log(logging.VERBOSE, '-> ' + to_hexstr(self.rx_bytes[:-2]))
                    self.rx_queue.put(self.rx_bytes[:-2])
                self.rx_bytes = b''
        
        self.com.close()
    
    def stop(self):
        self.alive = False
        self.join()
    
    def tx(self, data):
        self.logger.log(logging.VERBOSE, '<- ' + to_hexstr(data))
        data += modbus_crc(data).to_bytes(2, byteorder='little')
        self.com.write(data)

