FROM ubuntu:18.04
RUN apt-get -y update
RUN apt-get -y install python3 python3-pip python3-dev git libssl-dev libffi-dev build-essential
RUN python3 -m pip install --upgrade pip
RUN python3 -m pip install --upgrade git+https://github.com/Gallopsled/pwntools.git@dev
RUN apt-get -y install gdb
RUN apt-get -y install xterm
RUN git clone https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh
