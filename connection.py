import configparser
import threading

from scapy.all import *
from scapy.layers.inet import IP, TCP

CONFIG_FILE = 'config.ini'


# TODO: finish verbose outputs
# TODO: set timeout in send calls
# TODO: add log saving
# TODO: add default load list
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

        #  multithreading
        self._receiving_thread = None
        self._lock = threading.Lock()
        self._padding = True

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

        if self.connected:
            print('ERROR YOU ARE CURRENTLY CONNECTED')
            return

        try:
            # SYN
            self.ip = IP(src=self.src, dst=self.dst)
            syn = self.ip / TCP(sport=self.sport, dport=self.dport, flags='S', seq=self.seq)

            if verbose:
                print("============= SYN PACKET =============")
                syn.show()
                print("=======================================")

            # sending syn and waiting for syn_Ack response
            syn_ack = sr1(syn, timeout=self.timeout, verbose=False)

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

            send(ack, verbose=False)

            self.connected = True
            self._receiving_thread = threading.Thread(target=self._receiving_thread_func, args=())
            self._receiving_thread.start()

        except Exception as ex:
            print(ex)
            print("FAILED TO CONNECT, SENDING RESET")
            self.reset()

    # TODO: fix disconnect
    def disconnect(self, v=None):
        verbose = self.v if v is None else v
        received_finack = False

        # joining the receiving thread
        self.connected = False
        self._receiving_thread.join()

        self._lock.acquire()
        try:
            # sending fin and waiting for ack response
            fin = self.ip / TCP(sport=self.sport, dport=self.dport, flags="FA", seq=self.seq, ack=self.ack)
            ack = sr1(fin, timeout=self.timeout)
            self.seq += 1

            assert ack.haslayer(TCP), 'TCP layer missing'
            assert ack[TCP].flags == 'A', 'Did not response when ACK'

            # inner function to check for finack ot fin response from sniff
            def inner_disconnect(pkt):
                if pkt[TCP].flags == 'FA' or pkt[TCP].flags == 'F':
                    nonlocal received_finack
                    received_finack = True

            # sniff packets from dst until finack or fin is received
            while True:
                sniff(filter=' tcp and src host {} and port {}'.format(self.dst, self.sport), count=2,
                      prn=inner_disconnect, timeout=1)
                if received_finack:
                    break

            # response with ack
            ack = self.ip / TCP(sport=self.sport, dport=self.dport, flags='A', seq=self.seq, ack=self.ack)
            send(ack, verbose=False)

        except Exception as ex:
            print(ex)
            print("FAILED TO START DISCONNECT, SENDING RESET")
            self._lock.release()
            self.reset()
        finally:
            self._lock.release()

    def log(self, inbound):
        pass

    def reset(self, seq=None, v=None):
        verbose = self.v if v is None else v

        self._lock.acquire()
        try:
            # craft rst packet
            seq = seq if seq else self.seq
            ip = IP(src=self.src, dst=self.dst)
            rst = ip / TCP(sport=self.sport, dport=self.dport, flags="R", seq=seq)

            if verbose:
                print("=========== RESET PACKET ===========")
                rst.show()
                print('====================================')

            # send rst packet
            send(rst)

            # reset connection values
            self.base_ack = 0
            self.ack = 0
            self.seq = self.base_seq
            self.connected = False

            # if the receiving thread is not none have it return to the main thread
            if self._receiving_thread:
                self._receiving_thread.join()
                self._receiving_thread = None

        except Exception as ex:
            print(ex)
            print("FAILED TO SEND RESET")
        finally:
            self._lock.release()

    def save(self):
        config = configparser.ConfigParser()
        config['APP_CONFIG'] = {
            'src': self.src,
            'dst': self.dst,
            'sport': self.sport,
            'dport': self.dport,
            'timeout': self.timeout,
            'base_seq': self.base_seq,
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

        self._lock.acquire()
        try:
            # craft packet with payload
            pkt = self.ip / TCP(sport=self.sport, dport=self.dport, flags="PA", seq=self.seq, ack=self.ack) / payload

            if verbose:
                print("=========== SENDING PACKET ===========")
                pkt.show()
                print("=======================================")

            # send packet with payload and add payload length to seq
            ack = sr1(pkt, timeout=self.timeout, verbose=False)
            self.seq += len(payload)

            if verbose:
                print("============== RESPONSE ==============")
                ack.show()
                print("=======================================")

            assert ack.haslayer(TCP), 'TCP layer missing'
            assert ack[TCP].flags & 0x10 == 0x10, 'No ACK flag'

        except Exception as ex:
            print(ex)
            print("FAILED TO SEND PAYLOAD")
        finally:
            self._lock.release()

    def _receiving_thread_func(self):
        # loop while connection is active, the packets are passed to the _ack function
        while self.connected:
            sniff(filter=' tcp and src host {} and port {}'.format(self.dst, self.sport), count=2,
                  prn=self._ack, timeout=1)

    def _ack(self, pkt):
        # for some weird reason packets seem to be received twice, the first time with nothing but padding and a second
        # time with data. I'm using a little logic piece to ignore the first packet with only padding
        if self._padding:
            self._padding = False
            return
        else:
            self._padding = True

        print("============== RECEIVED ==============")
        pkt.show()
        print("=======================================")

        self._lock.acquire()
        try:
            # check for tcp layer
            assert pkt.haslayer(TCP), 'TCP layer missing'

            # check if a reset message was sent
            if pkt[TCP].flags == 'RA' or pkt[TCP].flags == 'R':
                print('THE CONNECTION WAS RESET')
                self.base_ack = 0
                self.ack = 0
                self.seq = self.base_seq
                self.connected = False
                return
            # check if a fin message was sent
            elif pkt[TCP].flags == 'FA' or pkt[TCP].flags == 'F':
                self.ack += 1
                ack = self.ip / TCP(sport=self.sport, dport=self.dport, flags="A", seq=self.seq, ack=self.ack)
                send(ack, verbose=False)
                self.seq += 1

                fin_ack = self.ip / TCP(sport=self.sport, dport=self.dport, flags="FA", seq=self.seq, ack=self.ack)
                send(fin_ack, verbose=False)
                self.connected = False
                return

            # acknowledge any data sent
            self.ack += len(pkt[TCP].load)
            ack = self.ip / TCP(sport=self.sport, dport=self.dport, flags='A', seq=self.seq, ack=self.ack)
            send(ack, verbose=False)

        except Exception as ex:
            print(ex)
        finally:
            self._lock.release()
