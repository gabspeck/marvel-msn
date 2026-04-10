#!/bin/fish
socat -d -d \
    pty,raw,echo=0,link=/tmp/vmodem \
    tcp-listen:2323,reuseaddr
