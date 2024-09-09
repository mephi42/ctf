# syntax=docker/dockerfile:1
ARG distro=ubuntu:latest
FROM $distro
ENV DEBIAN_FRONTEND=noninteractive
RUN [ ! -e /etc/apt/sources.list ] || sed -i -e '/^deb /{p;s/^deb /deb-src /g}' /etc/apt/sources.list
RUN [ ! -e /etc/apt/sources.list.d/debian.sources ] || sed -i -e 's/^Types: deb$/Types: deb deb-src/g' /etc/apt/sources.list.d/debian.sources
RUN apt-get -y update && \
    apt-get -y install --no-install-recommends \
        ca-certificates \
        curl \
        dpkg-dev \
        lsb-release
RUN (echo '#!/bin/sh' && \
     echo 'set -e -u -x' && \
     echo '[ "$(lsb_release --id --short)" = Ubuntu ] || exit 0' && \
     echo '[ "$3" != "*" ] || exit 0' && \
     echo 'url=https://launchpad.net/ubuntu/$(lsb_release --codename --short)/$2/$1/$3' && \
     echo 'url=$(curl "$url" | grep -o "http://launchpadlibrarian.net/[0-9]*/$1_$3_$2.deb")' && \
     echo 'cd /var/launchpadlibrarian' && \
     echo 'curl --remote-name "$url"') \
             >/usr/bin/launchpadlibrarian-dl && \
    chmod a+x /usr/bin/launchpadlibrarian-dl
RUN (echo '#!/bin/sh' && \
     echo 'set -e -u -x' && \
     echo '[ "$(lsb_release --id --short)" = Ubuntu ] || exit 0' && \
     echo '[ "$2" != "*" ] || exit 0' && \
     echo 'url=https://launchpad.net/ubuntu/+source/$1/$2' && \
     echo 'cd /var/launchpadlibrarian' && \
     echo 'for url in $(curl "$url" | grep -o "https://launchpad.net/ubuntu/+archive/primary/+sourcefiles/$1/$2/[^\"]*"); do' && \
     echo '    curl --location --remote-name "$url"' && \
     echo 'done') \
             >/usr/bin/launchpadlibrarian-dl-source && \
    chmod a+x /usr/bin/launchpadlibrarian-dl-source
RUN mkdir /var/launchpadlibrarian
ARG arch=amd64
ARG libc_version=*
RUN launchpadlibrarian-dl libc-dev-bin "$(dpkg --print-architecture)" "$libc_version"
RUN launchpadlibrarian-dl libc6 "$arch" "$libc_version"
RUN launchpadlibrarian-dl-source glibc "$libc_version"
RUN launchpadlibrarian-dl libc6-dbg "$arch" "$libc_version"
RUN launchpadlibrarian-dl libc6-dev "$arch" "$libc_version"
RUN cd /var/launchpadlibrarian && dpkg-scanpackages . >Packages
RUN cd /var/launchpadlibrarian && dpkg-scansources . >Sources
RUN (echo deb [trusted=yes] file:/var/launchpadlibrarian / && \
     echo deb-src [trusted=yes] file:/var/launchpadlibrarian /) \
             >/etc/apt/sources.list.d/launchpadlibrarian.list
RUN dpkg --add-architecture "$arch"
RUN apt-get -y update && \
    apt-get -y install --allow-downgrades --no-install-recommends \
        build-essential \
        dbus-x11 \
        dconf-cli \
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
ENV PIP_BREAK_SYSTEM_PACKAGES=1
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
