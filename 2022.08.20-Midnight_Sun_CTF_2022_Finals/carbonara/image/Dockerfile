FROM ubuntu:jammy
ENV DEBIAN_FRONTEND=noninteractive
RUN sed -i -e 's/^# deb-src /deb-src /g' /etc/apt/sources.list
RUN apt-get -y update && \
    apt-get -y install dpkg-dev gdb gdbserver libc6-dbg xterm wget
RUN cd /usr/src && apt-get source libstdc++6

# https://github.com/Gallopsled/pwntools#installation
RUN apt-get install -y python3 python3-pip python3-dev git libssl-dev libffi-dev build-essential
RUN python3 -m pip install --upgrade pip
RUN python3 -m pip install https://github.com/Gallopsled/pwntools/zipball/dev/ rpyc==4.1.5 z3-solver

# https://github.com/hugsy/gef#instant-setup
RUN wget https://gef.blah.cat/sh -O gef.sh && chmod a+x gef.sh && bash -e -x -o pipefail ./gef.sh

#RUN apt-get install -y --allow-downgrades libc6=2.35-0ubuntu3