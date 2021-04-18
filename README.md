# Net-Util
A small python command line tool used to automatically handle the TPC connection when using scapy

## Usage
To start the program please run the following command
```angular2html
sudo python3 net_util.py 
```

## Notice
this tool my fail to connect unless you run the following command
```
    iptables -A OUTPUT -p tcp --tcp-flags RST RST -s <INSERT IP> -j DROP
```
The reason is that the kernel is unaware of what scapy is doing and sends a RST packet when it sees incoming packets