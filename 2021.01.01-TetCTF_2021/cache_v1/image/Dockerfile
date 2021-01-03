FROM ubuntu:focal
ENV DEBIAN_FRONTEND=noninteractive
RUN sed -i -e 's/^# deb-src /deb-src /g' /etc/apt/sources.list
RUN apt-get -y update && \
    apt-get -y install dpkg-dev gdb libc6-dbg xterm wget
RUN cd /usr/src && apt-get source libstdc++6

# https://github.com/Gallopsled/pwntools#installation
RUN apt-get install -y python3 python3-pip python3-dev git libssl-dev libffi-dev build-essential
RUN python3 -m pip install --upgrade pip
RUN python3 -m pip install https://github.com/Gallopsled/pwntools/zipball/dev/ rpyc==4.1.5 z3-solver

# https://github.com/hugsy/gef#instant-setup
RUN wget https://github.com/hugsy/gef/raw/master/scripts/gef.sh && chmod a+x gef.sh && bash -e -u -x -o pipefail ./gef.sh

RUN mkdir /home/cache
RUN echo TetCTF{} >/home/cache/flag
