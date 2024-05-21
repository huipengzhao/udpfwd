#!/bin/bash

LOOPBACK=lo
[ $(uname -s) == "Darwin" ] && LOOPBACK=lo0

set -x
sudo tcpdump -n -i $LOOPBACK udp dst port 9002
