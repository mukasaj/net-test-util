import configparser

from scapy.layers.inet import IP, TCP
from scapy.all import *

CONFIG_FILE = 'config.ini'


# TODO: finish verbose outputs
# TODO: set timeout in send calls
# TODO: add log saving
class Connection:

    def __init__(self):
        if not os.path.isdir('logs'):
            os.mkdir('logs')

        config = configparser.ConfigParser()
        config.read(CONFIG_FILE)

        # application variables
        self.src = str(config['APP_CONFIG']['src']) if config.has_option('APP_CONFIG', 'src') else '1.1.1.1'
        self.dst = str(config['APP_CONFIG']['dst']) if config.has_option('APP_CONFIG', 'dst') else '1.1.1.1'
        self.dport = int(config['APP_CONFIG']['dport']) if config.has_option('APP_CONFIG', 'dport') else 10000
        self.sport = int(config['APP_CONFIG']['sport']) if config.has_option('APP_CONFIG', 'sport') else 10000
        self.timeout = int(config['APP_CONFIG']['timeout']) if config.has_option('APP_CONFIG', 'timeout') else 5
        self.base_seq = int(config['APP_CONFIG']['base_seq']) if config.has_option('APP_CONFIG', 'base_seq') else 1000
        v_string = config['APP_CONFIG']['verbose'] if config.has_option('APP_CONFIG', 'verbose') else 'False'
        self.v = True if v_string == 'True' else False

        # session/connection variables
        self.ip = None
        self.connected = False
        self.seq = self.base_seq
        self.base_ack = 0
        self.ack = self.base_ack

    def config(self, src=None, dst=None, sport=None, dport=None,
               timeout=None, base_seq=None, seq=None, ack=None, v=None):
        self.src = src if src else self.src
        self.dst = dst if dst else self.dst
        self.sport = sport if sport else self.sport
        self.dport = dport if dport else self.dport
        self.timeout = timeout if timeout else self.timeout
        self.base_seq = base_seq if base_seq else self.base_seq
        self.seq = seq if seq else self.seq
        self.ack = ack if ack else self.ack
        self.v = v if v is not None else self.v

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
            syn = self.ip / TCP(sport=self.sport, dport=self.dport, flags='S', seq=self.seq)

            if verbose:
                print("============= SYN PACKET =============")
                syn.show()
                print("=======================================")

            syn_ack = sr1(syn, timeout=self.timeout)

            if verbose:
                print("============== RESPONSE ==============")
                syn_ack.show()
                print("=======================================")

            assert syn_ack.haslayer(TCP), 'TCP layer missing'
            assert syn_ack[TCP].flags & 0x12 == 0x12, 'No SYN/ACK flags'

            # Updating seq and ack numbers
            self.seq += 1
            self.base_ack = syn_ack.seq
            self.ack = self.base_ack
            self.ack += 1

            assert syn_ack[TCP].ack == self.seq, 'Acknowledgment number error'

            # sending ack response
            ack = self.ip / TCP(sport=self.sport, dport=self.dport, flags='A', seq=self.seq, ack=self.ack)

            if verbose:
                print("============ ACK PACKET ============")
                syn_ack.show()
                print("=======================================")

            send(ack)

            self.connected = True
        except Exception as ex:
            print(ex)
            print("FAILED TO CONNECT, SENDING RESET")
            self.reset()

    # TODO: fix disconnect
    def disconnect(self, v=None):
        verbose = self.v if v is None else v
        try:
            fin = self.ip / TCP(sport=self.sport, dport=self.dport, flags="FA", seq=self.seq, ack=self.ack)
            ack_fin_ack = sr1(fin, timeout=self.timeout, multi=1)
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

    def log(self, inbound):
        pass

    def reset(self, seq=None, v=None):
        verbose = self.v if v is None else v
        try:
            seq = seq if seq else self.seq
            ip = IP(src=self.src, dst=self.dst)
            rst = ip / TCP(sport=self.sport, dport=self.dport, flags="R", seq=seq)

            if verbose:
                print("=========== RESET PACKET ===========")
                rst.show()
                print('====================================')
            send(rst)

            self.base_ack = 0
            self.ack = 0
            self.seq = self.base_seq
            self.connected = False
        except Exception as ex:
            print(ex)
            print("FAILED TO SEND RESET")

    def save(self):
        config = configparser.ConfigParser()
        config['APP_CONFIG'] = {
            'src': self.src,
            'dst': self.dst,
            'sport': self.sport,
            'dport': self.dport,
            'timeout': self.timeout,
            'base_seq': self.seq,
            'verbose': self.v
        }
        with open(CONFIG_FILE, 'w') as config_file:
            config.write(config_file)
            print("Configuration saved")

    def send(self, payload, v=None):
        verbose = self.v if v is None else v

        if self.connected is False:
            print("ERROR, not connected")
            return

        try:
            pkt = self.ip / TCP(sport=self.sport, dport=self.dport, flags="PA", seq=self.seq, ack=self.ack) / payload

            if verbose:
                print("=========== SENDING PACKET ===========")
                pkt.show()
                print("=======================================")

            ack = sr1(pkt, timeout=self.timeout)

            if verbose:
                print("============== RESPONSE ==============")
                pkt.show()
                print("=======================================")

            self.seq += len(payload)
            self.ack = ack.seq

            if verbose:
                ack.show()

            assert ack.haslayer(TCP), 'TCP layer missing'
            assert ack[TCP].flags & 0x10 == 0x10, 'No ACK flag'

        except Exception as ex:
            print(ex)
            print("FAILED TO SEND PAYLOAD")
