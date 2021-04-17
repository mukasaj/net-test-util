import random
import socket

from scapy.layers.inet import IP, TCP
from scapy.all import *


# s = socket.socket()
#
# s.connect(("192.168.59.129", 179))
# ss = StreamSocket(s)
#
# ss.send(BGP())
# ss.close()

class Connection:

    def __init__(self):
        self.timeout = 5
        self.dport = 64444
        self.sport = 64444 #random.randint(30000, 65000)
        self.src = '192.168.59.128'
        self.dst = '192.168.59.129'
        self.connected = False
        self.ip = None
        self.ack = None
        self.base_seq = 1000
        self.seq = 1000

    def config(self, src=None, dst=None, sport=None, dport=None, timeout=None, base_seq=None, seq=None):
        self.src = src if src else self.src
        self.dst = dst if dst else self.dst
        self.sport = sport if sport else self.sport
        self.dport = dport if dport else self.dport
        self.timeout = timeout if timeout else self.timeout
        self.base_seq = base_seq if base_seq else self.base_seq
        self.seq = seq if seq else self.seq

        print('''
    source ip(src):             {}
    destination ip(dst):        {}
    source port(sport):         {}
    destination port(dport):    {}
    timeout:                    {}
    base seq number:            {}
    current seq number(seq)     {}
        '''.format(
            self.src,
            self.dst,
            self.sport,
            self.dport,
            self.timeout,
            self.base_seq,
            self.seq
        ))

    def connect(self):
        try:
            # SYN
            self.ip = IP(src=self.src, dst=self.dst)
            syn = TCP(sport=self.sport, dport=self.dport, flags='S', seq=self.seq)
            syn_ack = sr1(self.ip / syn)

            syn_ack.show()
            print("old seq {}".format(self.seq))
            self.seq += 1
            print("new seq {}".format(self.seq))

            print("old ack {}".format(self.ack))
            self.ack = syn_ack.seq
            print("new ack {}".format(self.ack))

            # SYN-ACK
            self.ack += 1
            ack = TCP(sport=self.sport, dport=self.dport, flags='A', seq=self.seq, ack=self.ack)

            send(self.ip / ack)
            self.connected = True
        except Exception as ex:
            print(ex)
            print("FAILED TO CONNECT")

    def disconnect(self):
        try:
            fin = self.ip / TCP(sport=self.sport, dport=self.dport, flags="FA", seq=self.seq, ack=self.ack)
            ack_fin_ack = sr1(fin, timeout=1, multi=1)
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
            print("FAILED TO DISCONNECT")

    def reset(self, seq=None):
        try:
            seq = seq if seq else self.seq
            ip = IP(src=self.src, dst=self.dst)
            send(ip / TCP(sport=self.sport, dport=self.dport, flags="R", seq=seq))
            self.connected = False
        except Exception as ex:
            print(ex)
            print("FAILED TO SEND RESET")

    def send(self, payload):
        if self.connected is False:
            print("ERROR, not connected")
            return

        try:
            pkt = self.ip / TCP(sport=self.sport, dport=self.dport, flags="PA", seq=self.ack, ack=self.seq) / payload

            ack = sr1(pkt, timeout=self.timeout)

            ack.show()
            print("++++++++++++++++++++++++++++++++++++++++++++++++")
            print(ack[TCP].seq)
            print("++++++++++++++++++++++++++++++++++++++++++++++++")
            print("old seq {}".format(self.seq))
            self.seq += len(payload)
            print("new seq {}".format(self.seq))

            print("old ack {}".format(self.ack))
            self.ack = self.ack
            print("new ack {}".format(self.ack))

            assert ack.haslayer(TCP), 'TCP layer missing'
            assert ack[TCP].flags & 0x10 == 0x10, 'No ACK flag'


        except Exception as ex:
            print(ex)
            print("FAILED TO SEND PAYLOAD")
