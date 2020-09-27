FROM ubuntu:bionic
ENV DEBIAN_FRONTEND=noninteractive
RUN sed -i -e 's/^# deb-src /deb-src /g' /etc/apt/sources.list
RUN apt-get -y update
RUN apt-get -y install dpkg-dev g++ gdb ncurses-dev xterm wget

RUN apt-get install -y python3 python3-pip python3-dev git libssl-dev libffi-dev build-essential
RUN python3 -m pip install --upgrade pip
RUN python3 -m pip install --upgrade pwntools

RUN apt-get -y install valgrind

RUN apt-get -y install libc6-dbg

RUN apt-get -y install locales
RUN locale-gen en_US.UTF-8 && update-locale

# Sometimes Ctrl+C kills GDB, but this is not GEF's fault.
# RUN wget https://github.com/hugsy/gef/raw/master/scripts/gef.sh && chmod a+x gef.sh && bash -e -u -x ./gef.sh
# pwndbg interferes with scripting (specifically, in `b + commands` commands
# are ignored).
# RUN git clone https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh
