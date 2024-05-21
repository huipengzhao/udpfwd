#!/usr/bin/env python3
import socket,sys,os,datetime,time

ADDR_SRC = ('127.0.0.1', 9000)
ADDR_DST = ('127.0.0.1', 9001)
ADDR_FWD = ('127.0.0.1', 9002)

UDPFWD=f'sudo udpfwd -i lo -o {ADDR_FWD[1]} udp dst port {ADDR_DST[1]}'
TCPDUMP=f'sudo tcpdump -n -i lo udp dst port {ADDR_FWD[1]}'

def main():
    # terminal1: ./test.py
    # terminal2: sudo ./udpfwd -i lo -o 9002 udp dst port 9001
    # terminal3: sudo tcpdump -n -i lo udp dst port 9002
    # terminal4: nc -ul 9002
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(ADDR_SRC)
    while True:
        msg = 'helloworld ' + datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S.%f') + '\n'
        print('send from'+str(ADDR_SRC)+' to'+str(ADDR_DST)+': ('+str(len(msg))+') '+msg.rstrip('\n'))
        try:
            sock.sendto(msg.encode(), ADDR_DST)
            time.sleep(1)
        except KeyboardInterrupt:
            print('KeyboardInterrupt')
            break
    sock.close()
    return

if __name__ == '__main__':
    main()