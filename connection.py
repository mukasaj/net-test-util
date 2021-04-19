import random
import socket
import pickle

from scapy.layers.inet import IP, TCP
from scapy.all import *


class Connection:

    def __init__(self):

        # application variables
        self.src = '192.168.59.128'
        self.dst = '192.168.59.129'
        self.dport = 64444
        self.sport = 64444
        self.timeout = 5
        self.base_seq = 1000
        self.v = False

        # session/connection variables
        self.ip = None
        self.connected = False
        self.seq = self.base_seq
        self.base_ack = 0
        self.ack = self.base_ack

    def config(self, src=None, dst=None, sport=None, dport=None, timeout=None, base_seq=None, seq=None, ack=None):
        self.src = src if src else self.src
        self.dst = dst if dst else self.dst
        self.sport = sport if sport else self.sport
        self.dport = dport if dport else self.dport
        self.timeout = timeout if timeout else self.timeout
        self.base_seq = base_seq if base_seq else self.base_seq
        self.seq = seq if seq else self.seq
        self.ack = ack if ack else self.ack

        print('''
    ==== APPLICATION CONFIGURATION ====
    source ip(src):             {}
    destination ip(dst):        {}
    source port(sport):         {}
    destination port(dport):    {}
    timeout(timeout):           {}
    base seq number(base_seq):  {}
    verbose(v):                 {}
    
    ==== SESSION DATA ====
    connection status           {}
    current seq number(seq)     {}({})
    base ack number:            {}
    current ack number(ack):    {}({})
        '''.format(
            self.src,
            self.dst,
            self.sport,
            self.dport,
            self.timeout,
            self.base_seq,
            self.v,
            True if self.connected else False,
            self.seq,
            self.seq - self.base_seq,
            self.base_ack,
            self.ack,
            self.ack - self.base_ack
        ))

    def is_connected(self):
        return self.connected

    def connect(self, v=None):
        verbose = self.v if v is None else v
        try:
            # SYN
            self.ip = IP(src=self.src, dst=self.dst)
            syn = TCP(sport=self.sport, dport=self.dport, flags='S', seq=self.seq)
            syn_ack = sr1(self.ip / syn)

            if verbose:
                print("========== RESPONSE FROM SYN ==========")
                syn_ack.show()
                print("=======================================")

            # incrementing seq since syn has a phantom byte
            self.seq += 1

            # setting ack number using seq from response
            self.base_ack = syn_ack.seq
            self.ack = self.base_ack

            # incrementing ack from phantom byte in SYN ACK response
            self.ack += 1

            assert syn_ack.haslayer(TCP), 'TCP layer missing'
            assert syn_ack[TCP].flags & 0x12 == 0x12, 'No SYN/ACK flags'
            assert syn_ack[TCP].ack == self.seq, 'Acknowledgment number error'

            # sending ack response
            ack = TCP(sport=self.sport, dport=self.dport, flags='A', seq=self.seq, ack=self.ack)
            send(self.ip / ack)

            self.connected = True
        except Exception as ex:
            print(ex)
            print("FAILED TO CONNECT")

    def disconnect(self, v=None):
        verbose = self.v if v is None else v
        try:
            fin = self.ip / TCP(sport=self.sport, dport=self.dport, flags="FA", seq=self.seq, ack=self.ack)
            ack_fin_ack = sr1(fin, timeout=15, multi=1)
            ack = ack_fin_ack[0]
            fin_ack = ack_fin_ack[1]

            assert fin_ack.haslayer(TCP), 'TCP layer missing'
            assert fin_ack[TCP].flags & 0x11 == 0x11, 'No FIN/ACK flags, received \'{}\''.format(fin_ack[TCP].flags)

            last_ack = self.ip / TCP(sport=self.sport, dport=self.dport, flags="A", seq=ack.seq,
                                     ack=ack.ack)
            send(last_ack)
            self.connected = False
        except Exception as ex:
            print(ex)
            print("FAILED TO DISCONNECT, SENDING RESET")
            self.reset()

    def reset(self, seq=None, v=None):
        verbose = self.v if v is None else v
        try:
            seq = seq if seq else self.seq
            ip = IP(src=self.src, dst=self.dst)
            rst = ip / TCP(sport=self.sport, dport=self.dport, flags="R", seq=seq)

            if verbose:
                rst.show()

            send(rst)

            self.base_ack = 0
            self.ack = 0
            self.seq = self.base_seq
            self.connected = False
        except Exception as ex:
            print(ex)
            print("FAILED TO SEND RESET")

    def save(self):
        config = {
            'src': self.src,
            'dst': self.dst,
            'sport': self.sport,
            'dport': self.dport,
            'timeout': self.timeout,
            'base_seq': self.seq,
            'verbose': self.v
        }
        config_file = open('configuration', 'wb')
        pickle.dumo(config, config_file)
        config_file.close()

    def send(self, payload, v=None):
        verbose = self.v if v is None else v

        if self.connected is False:
            print("ERROR, not connected")
            return

        try:
            pkt = self.ip / TCP(sport=self.sport, dport=self.dport, flags="PA", seq=self.seq, ack=self.ack) / payload

            ack = sr1(pkt, timeout=self.timeout)

            self.seq += len(payload)
            self.ack = ack.seq

            if verbose:
                ack.show()

            assert ack.haslayer(TCP), 'TCP layer missing'
            assert ack[TCP].flags & 0x10 == 0x10, 'No ACK flag'

        except Exception as ex:
            print(ex)
            print("FAILED TO SEND PAYLOAD")
