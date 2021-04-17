import readline

from connection import Connection
from scapy.all import *

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


if __name__ == '__main__':
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
