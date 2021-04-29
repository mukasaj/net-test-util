import readline
import signal
import sys

from connection import Connection
from scapy.all import *

VERSION = '0.4'
HISTORY_FILE = '.history'

# iptables -A OUTPUT -p tcp --tcp-flags RST RST -s 192.168.1.20 -j DROP

connection = Connection()


def config(*args, **kwarg):
    connection.config(*args, **kwarg)


def load(*args, **kwargs):
    """
    load(*args, **kwargs)
        passes args and kwargs into scapy load_contrib function, please read scapy docs for more info
        :param args: passing args to scapy load_contrib function
        :param kwargs: passing kwargs to scapy load_contrib function
    """
    load_contrib(*args, **kwargs)


def connect(*args, **kwarg):
    connection.connect(*args, **kwarg)


def disconnect(*args, **kwargs):
    connection.disconnect(*args, **kwargs)


def send(*args, **kwarg):
    connection.send(*args, **kwarg)


def fsend(*args, **kwarg):
    connection.fsend(*args, **kwarg)


def ssend(*args, **kwargs):
    """
    ssend(*args, **kwargs)
        passes args and kwargs into scapy send function, please read scapy docs for more info
        :param args: passing args to scapy send function
        :param kwargs: passing kwargs to scapy send function
    """
    scapy.all.send(*args, **kwargs)


def save(*args, **kwarg):
    connection.save(*args, **kwarg)


def reset(*args, **kwarg):
    connection.reset(*args, **kwarg)


def help():
    print('DOC STRINGS')
    print(connection.config.__doc__)
    print(connection.connect.__doc__)
    print(connection.disconnect.__doc__)
    print(connection.log.__doc__)
    print(load.__doc__)
    print(connection.save.__doc__)
    print(connection.fsend.__doc__)
    print(ssend.__doc__)
    print(connection.send.__doc__)
    print(connection.reset.__doc__)


def exit():
    readline.write_history_file('history')
    connection.close()
    print("\nGoodbye")
    sys.exit()


def sigint_handler(sig, frame):
    exit()


if __name__ == '__main__':
    signal.signal(signal.SIGINT, sigint_handler)
    print("net-util v{}".format(VERSION))
    readline.read_history_file('history')
    while True:
        val = input(">>>")
        if val == '':
            continue
        elif val == 'help':
            help()
            continue
        elif val == 'exit':
            exit()
            break
        try:
            exec(val)
        except Exception as e:
            print(e)
