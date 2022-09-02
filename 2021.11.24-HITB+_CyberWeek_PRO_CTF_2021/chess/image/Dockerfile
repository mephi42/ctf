FROM ubuntu@sha256:26cd4ff32a9c031eaca3d6f589a7799f28b34a539e1bd81acbf1a6efeec4b1ce
ENV DEBIAN_FRONTEND=noninteractive
RUN sed -i -e 's/^# deb-src /deb-src /g' /etc/apt/sources.list
RUN apt-get -y update && \
    apt-get -y install dpkg-dev gdb libc6-dbg xterm wget
RUN cd /usr/src && apt-get source libstdc++6

# https://github.com/Gallopsled/pwntools#installation
RUN apt-get install -y python3 python3-pip python3-dev git libssl-dev libffi-dev build-essential
RUN python3 -m pip install --upgrade pip
RUN python3 -m pip install https://github.com/Gallopsled/pwntools/zipball/dev/ rpyc==4.1.5

# https://github.com/hugsy/gef#instant-setup
RUN wget https://github.com/hugsy/gef/raw/master/scripts/gef.sh && chmod a+x gef.sh && bash -e -u -x -o pipefail ./gef.sh
