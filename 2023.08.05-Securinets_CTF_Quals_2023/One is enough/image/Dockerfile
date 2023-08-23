# syntax=docker/dockerfile:1
ARG distro=ubuntu:latest
FROM $distro
ARG arch=amd64
ARG libc_version=*
ENV DEBIAN_FRONTEND=noninteractive
RUN sed -i -e '/^deb /{p;s/^deb /deb-src /g}' /etc/apt/sources.list
RUN dpkg --add-architecture "$arch"
RUN apt-get -y update && \
    apt-get -y install --no-install-recommends \
        build-essential \
        curl \
        dbus-x11 \
        dconf-cli \
        dpkg-dev \
        file \
        gdb-multiarch \
        gdbserver \
        git \
        gnome-terminal \
        libc-dev-bin="$libc_version" \
        libc6:"$arch"="$libc_version" \
        libc6-dbg:"$arch"="$libc_version" \
        libc6-dev:"$arch"="$libc_version" \
        libcanberra-gtk3-module \
        libffi-dev \
        libssl-dev \
        lsb-release \
        procps \
        python3 \
        python3-dev \
        python3-pip \
        qemu-user \
        strace \
        sudo \
        vim \
        wget
RUN cd /usr/src && apt-get source libc6="$(dpkg -s libc6:"$arch" | awk '/^Version:/ { print $2; }')"
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
