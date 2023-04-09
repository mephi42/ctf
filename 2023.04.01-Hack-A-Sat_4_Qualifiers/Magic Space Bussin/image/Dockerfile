# syntax=docker/dockerfile:1
ARG ubuntu_version=latest
FROM ubuntu:$ubuntu_version
ARG libc_version=*
ENV DEBIAN_FRONTEND=noninteractive
RUN sed -i -e 's/^# deb-src /deb-src /g' /etc/apt/sources.list
RUN apt-get -y update && \
    apt-get -y install --no-install-recommends \
        build-essential \
        curl \
        dbus-x11 \
        dconf-cli \
        dpkg-dev \
        file \
        gdb \
        gdbserver \
        git \
        gnome-terminal \
        libc-dev-bin="$libc_version" \
        libc6="$libc_version" \
        libc6-dbg="$libc_version" \
        libc6-dev="$libc_version" \
        libcanberra-gtk3-module \
        libffi-dev \
        libssl-dev \
        lsb-release \
        procps \
        python3 \
        python3-dev \
        python3-pip \
        strace \
        sudo \
        vim \
        wget
RUN cd /usr/src && apt-get source libc6="$libc_version"
RUN python3 -m pip install --upgrade pip
RUN python3 -m pip install \
        pwntools \
        rpyc \
        z3-solver
RUN bash -c "$(curl -fsSL https://gef.blah.cat/sh)"
RUN dbus-launch dconf load / <<EOF
[org/gnome/terminal/legacy/profiles:/:b1dcc9dd-5262-4d8d-a863-c897e6d979b9]
background-color='rgb(0,0,0)'
foreground-color='rgb(255,255,255)'
use-theme-colors=false
EOF
