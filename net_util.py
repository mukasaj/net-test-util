import readline
import signal
import sys

from connection import Connection
from scapy.all import *

VERSION = '0.4'
HISTORY_FILE = '.history'

# iptables -A OUTPUT -p tcp --tcp-flags RST RST -s 192.168.1.20 -j DROP

connection = Connection()


def config(**kwargs):
    connection.config(**kwargs)


def load(module):
    load_contrib(module)


def show(pkt):
    pkt.show()


def connect(**kwargs):
    connection.connect(**kwargs)


def disconnect(**kwargs):
    connection.disconnect(**kwargs)


def send(payload, **kwargs):
    connection.send(payload, **kwargs)

def fsend(payload, **kwargs):
    connection.fsend(payload, **kwargs)

def ssend(*args, **kwargs):
    scapy.all.send(*args, **kwargs)

def save():
    connection.save()


def reset(**kwargs):
    connection.reset(**kwargs)


def help():
    print('''
    connect() - connect to server
    disconnect() - disconnect from server
    load(<contrib name>) - loads contrib module
    save() - saves the application configuration
    send(<data>) - sends packet(s)
    fsend(<data>) - sends packet(s) 
    show(<scapy packet>) - shows a scapy packet
    reset() - resets the connection
    ''')


def exit():
    readline.write_history_file('history')
    if connection.is_connected():
        print("\nsending RST packet to open connection")
        connection.reset()
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
        try:
            exec(val)
        except Exception as e:
            print(e)
