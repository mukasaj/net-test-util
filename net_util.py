import readline
import signal
import sys

from connection import Connection
from scapy.all import *

VERSION = '0.1.1'

# iptables -A OUTPUT -p tcp --tcp-flags RST RST -s 192.168.1.20 -j DROP

connection = Connection()


def config(**kwargs):
    connection.config(**kwargs)


def load(module):
    load_contrib(module)


def connect():
    connection.connect()


def disconnect():
    connection.disconnect()


def send(payload):
    connection.send(payload)


def reset(**kwargs):
    connection.reset(**kwargs)


def ntu_help():
    print('''
        connect() - connect to server
        disconnect() = disconnect from server
        load(<contrib name>) - loads contrib module
        send(<packet>) - sends packet(s)
        reset() - resets the connection
    ''')


def exit():
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
    while True:
        val = input(">>>")
        if val == 'help':
            ntu_help()
            continue
        if val == '':
            continue
        try:
            exec(val)
        except Exception as e:
            print(e)
