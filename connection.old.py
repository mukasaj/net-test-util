#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# Author: N0dr4x (n0dr4x@protonmail.com)

'''
Simple Scapy TCP Session class that provide ability
to : 
   - execute the 3-way handshake (eg. connect)
   - properly close connection (->FIN/ACK, <-FIN/ACK, ->ACK )
   - send automatic acknowledgment of received tcp data packet
   - build a next packet to send with correct sequence number
   - directly send data through the session
HINT : Don't forget to block TCP/RST packet that was send
       by the linux kernel because no source port was bound.

         # iptables -A OUTPUT -p tcp --sport 1337 --tcp-flags RST RST -j DROP
Source port is, for now, fixed to 1337 to facilitate wireshark filtering.
The purpose of this class is to easily build a working tcp session and
have complete scapy control of the next tcp packet.
Usage & example :

   # # Create the session object and connect to host 192.168.13.37 port 80
   # >>> sess = TcpSession(('192.168.13.37',80))
   # >>> sess.connect()
   # # Build next packet and send it fragmented (layer 2)
   # >>> p = sess.build('GET / HTTP/1.1\r\n\r\n')
   # >>> send(fragment(p, fragsize=16))
   # # Direct send data through the session and close
   # >>> sess.send('GET /index.html HTTP/1.1\r\n\r\n')
   # >>> sess.close()
   # # Session object can be reusable
   # >>> sess.connect()
   # >>> sess.send('GET /robot.txt HTTP/1.1\r\n\r\n')
   # >>> sess.close()
TODO :
   1/ Optionally dump received data to a file
   2/ Proper logging
'''

from scapy.all import *
from threading import Thread

from scapy.contrib.bgp import BGP, BGPUpdate
from scapy.layers.inet import TCP, IP


class TcpSession:

    def __init__(self):
        self.seq = 0
        self.ack = 0
        self.ip = IP(dst="192.168.59.129")
        self.sport = 1337
        self.dport = 179
        self.connected = False
        self._ackThread = None
        self._timeout = 10

    def _ack(self, p):
        self.ack = p[TCP].seq + len(p[Raw])
        ack = self.ip / TCP(sport=self.sport, dport=self.dport, flags='A', seq=self.seq, ack=self.ack)
        send(ack)

    def _ack_rclose(self):
        self.connected = False

        self.ack += 1
        fin_ack = self.ip / TCP(sport=self.sport, dport=self.dport, flags='FA', seq=self.seq, ack=self.ack)
        ack = sr1(fin_ack, timeout=self._timeout)
        self.seq += 1

        assert ack.haslayer(TCP), 'TCP layer missing'
        assert ack[TCP].flags & 0x10 == 0x10, 'No ACK flag'
        assert ack[TCP].ack == self.seq, 'Acknowledgment number error'

    def _sniff(self):
        s = L3RawSocket()
        while self.connected:
            p = s.recv(MTU)
            if p.haslayer(TCP) and p.haslayer(Raw) \
                    and p[TCP].dport == self.sport:
                self._ack(p)
            if p.haslayer(TCP) and p[TCP].dport == self.sport \
                    and p[TCP].flags & 0x01 == 0x01:  # FIN
                self._ack_rclose()

        s.close()
        self._ackThread = None
        print('Acknowledgment thread stopped')

    def _start_ackThread(self):
        self._ackThread = Thread(name='AckThread', target=self._sniff)
        self._ackThread.start()

    def connect(self):
        self.seq = random.randrange(0, (2 ** 32) - 1)

        syn = self.ip / TCP(sport=self.sport, dport=self.dport, seq=self.seq, flags='S')
        syn_ack = sr1(syn, timeout=self._timeout)
        self.seq += 1

        assert syn_ack.haslayer(TCP), 'TCP layer missing'
        assert syn_ack[TCP].flags & 0x12 == 0x12, 'No SYN/ACK flags'
        assert syn_ack[TCP].ack == self.seq, 'Acknowledgment number error'

        self.ack = syn_ack[TCP].seq + 1
        ack = self.ip / TCP(sport=self.sport, dport=self.dport, seq=self.seq, flags='A', ack=self.ack)
        send(ack)

        self.connected = True
        self._start_ackThread()
        print('Connected')

    def close(self):
        self.connected = False

        fin = self.ip / TCP(sport=self.sport, dport=self.dport, flags='FA', seq=self.seq, ack=self.ack)
        fin_ack = sr1(fin, timeout=self._timeout)
        self.seq += 1

        assert fin_ack.haslayer(TCP), 'TCP layer missing'
        assert fin_ack[TCP].flags & 0x11 == 0x11, 'No FIN/ACK flags'
        assert fin_ack[TCP].ack == self.seq, 'Acknowledgment number error'

        self.ack = fin_ack[TCP].seq + 1
        ack = self.ip / TCP(sport=self.sport, dport=self.dport, flags='A', seq=self.seq, ack=self.ack)
        send(ack)

        print('Disconnected')

    def build(self, payload):
        psh = self.ip / TCP(sport=self.sport, dport=self.dport, flags='PA', seq=self.seq, ack=self.ack) / payload
        print(psh)
        self.seq += len(raw(psh))
        return psh

    def send(self, payload):
        psh = self.build(payload)
        ack = sr1(psh, timeout=self._timeout)

        assert ack.haslayer(TCP), 'TCP layer missing'
        assert ack[TCP].flags & 0x10 == 0x10, 'No ACK flag'
        assert ack[TCP].ack == self.seq, 'Acknowledgment number error'


if __name__ == '__main__':
    tcp_session = TcpSession()
    tcp_session.connect()
    tcp_session.send(BGPUpdate())
    tcp_session.close()

import random
import time

from scapy.contrib.bgp import BGPUpdate, BGP
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sr1, send
#
# dport = 179
# sport = random.randint(30000, 65000)
# src = '192.168.59.128'
# dst = '192.168.59.129'
#
# # SYN
# ip = IP(src=src, dst=dst)
# SYN = TCP(sport=sport, dport=dport, flags='S', seq=1000)
# SYNACK = sr1(ip / SYN)
#
# # SYN-ACK
# ACK = TCP(sport=sport, dport=dport, flags='A', seq=SYNACK.ack, ack=SYNACK.seq+1)
# send(ip / ACK)
#
# send(ip / TCP(sport=sport, dport=dport, flags="PA", seq=SYNACK.ack, ack=SYNACK.seq+1) / BGP())
# time.sleep(1)
# send(ip / TCP(sport=sport, dport=dport, flags="R"))
#
#
# FIN = ip / TCP(sport=sport, dport=dport, flags="FA", seq=SYNACK.ack, ack=SYNACK.seq + 1)
# FINACK = sr1(FIN, timeout=1, multi=1)
#
# # assert FINACK[1].haslayer(TCP), 'TCP layer missing'
# # assert FINACK[1][TCP].flags & 0x11 == 0x11, 'No FIN/ACK flags'
#
# LASTACK = ip / TCP(sport=sport, dport=dport, flags="A", seq=FINACK[0].ack, ack=FINACK[0].seq)
# send(LASTACK)
