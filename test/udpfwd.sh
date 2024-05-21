#!/bin/bash

LOOPBACK=lo
[ $(uname -s) = 'Darwin' ] && LOOPBACK=lo0

set -x
sudo ./udpfwd -i $LOOPBACK -o 9002 udp dst port 9001
