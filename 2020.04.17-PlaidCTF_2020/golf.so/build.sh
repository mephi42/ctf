#!/bin/sh
set -e -u -x
gcc -c -o hardcore-golf.o hardcore-golf.S
objcopy -O binary hardcore-golf.o golf.so
ls -l golf.so
readelf -a golf.so
LD_DEBUG=all LD_PRELOAD=./golf.so /bin/true
