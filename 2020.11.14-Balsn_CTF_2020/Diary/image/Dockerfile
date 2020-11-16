FROM ubuntu:disco-20200114
ENV DEBIAN_FRONTEND=noninteractive
RUN sed -i -re 's/([a-z]{2}\.)?archive.ubuntu.com|security.ubuntu.com/old-releases.ubuntu.com/g' /etc/apt/sources.list
RUN sed -i -e 's/^# deb-src /deb-src /g' /etc/apt/sources.list
RUN apt-get -y update && \
    apt-get -y install dpkg-dev g++ gdb libc6-dbg ncurses-dev valgrind xterm wget

# https://github.com/Gallopsled/pwntools#installation
RUN apt-get install -y python3 python3-pip python3-dev git libssl-dev libffi-dev build-essential
RUN python3 -m pip install --upgrade pip
RUN python3 -m pip install git+https://github.com/mephi42/pwntools.git@gdb-api

# https://github.com/hugsy/gef#instant-setup
RUN wget https://github.com/hugsy/gef/raw/master/scripts/gef.sh && chmod a+x gef.sh && bash -e -u -x ./gef.sh

# https://github.com/pwndbg/pwndbg#how
# RUN git clone https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh
