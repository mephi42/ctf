FROM ubuntu:bionic
ENV DEBIAN_FRONTEND=noninteractive
RUN sed -i -e 's/^# deb-src /deb-src /g' /etc/apt/sources.list
RUN apt-get -y update && \
    apt-get -y install dpkg-dev gdb libc6-dbg xterm wget

# https://github.com/Gallopsled/pwntools#installation
RUN apt-get install -y python3 python3-pip python3-dev git libssl-dev libffi-dev build-essential
RUN python3 -m pip install --upgrade pip
RUN python3 -m pip install git+https://github.com/Gallopsled/pwntools.git

# https://github.com/hugsy/gef#instant-setup
RUN wget https://github.com/hugsy/gef/raw/master/scripts/gef.sh && chmod a+x gef.sh && bash -e -u -x ./gef.sh

# https://github.com/pwndbg/pwndbg#how
# RUN git clone https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh
