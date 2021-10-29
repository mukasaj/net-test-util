import socket
import sys

IP = str(sys.argv[1])     # get IP from command line
PORT = int(sys.argv[2])     # get PORT from command line

print("listening at {}:{}".format(IP, PORT))
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((IP, PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print('Connected by', addr)
        while True:
            data = conn.recv(1024)
            if data:
                print(data)
            if not data:
                break
            conn.send(data)

