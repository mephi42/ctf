FROM ubuntu:24.04 AS qemu-9.2.2
ENV DEBIAN_FRONTEND=noninteractive
RUN sed -i 's/^Types: deb/Types: deb deb-src/g' /etc/apt/sources.list.d/ubuntu.sources
RUN apt-get -y update && apt-get -y install \
        ninja-build \
        python3-pip \
        python3-tomli \
        tar \
        wget \
        xz-utils
RUN apt-get -y update && apt-get -y build-dep \
        qemu
WORKDIR /tmp
COPY Makefile.qemu .
RUN make -f Makefile.qemu -j"$(nproc)" qemu-9.2.2/configure
RUN make -f Makefile.qemu -j"$(nproc)" install

FROM ubuntu:24.04 AS buildroot-2025.02-toolchain
ENV DEBIAN_FRONTEND=noninteractive
ENV FORCE_UNSAFE_CONFIGURE=1
RUN apt-get -y update && apt-get -y install \
        bc \
        bzip2 \
        ccache \
        clang \
        cpio \
        file \
        g++ \
        gcc \
        git \
        libelf-dev \
        llvm \
        make \
        python3 \
        rsync \
        tar \
        unzip \
        wget \
        xz-utils
ENV PATH=/usr/lib/ccache:$PATH
WORKDIR /tmp
RUN wget https://buildroot.org/downloads/buildroot-2025.02.tar.xz
RUN tar xvJf buildroot-2025.02.tar.xz
WORKDIR /tmp/buildroot-2025.02
COPY buildroot-2025.02 ./
RUN make -j"$(nproc)" olddefconfig
RUN --mount=type=cache,target=/root/.ccache \
    --mount=type=cache,target=/tmp/buildroot-2025.02/dl \
    make \
        -j"$(nproc)" \
        host-bpftool \
        toolchain \
        BPFTOOL_VERSION=v7.5.0 \
        BR_NO_CHECK_HASH_FOR=bpftool-v7.5.0-git4.tar.gz

FROM buildroot-2025.02-toolchain AS buildroot-2025.02
RUN --mount=type=cache,target=/root/.ccache \
    --mount=type=cache,target=/tmp/buildroot-2025.02/dl \
    make -j"$(nproc)" BR_NO_CHECK_HASH_FOR=linux-6.13.11.tar.xz
ENV CC=/tmp/buildroot-2025.02/output/host/bin/x86_64-buildroot-linux-musl-gcc
COPY deactivate ./deactivate/
RUN cd deactivate && \
    make CC="$CC" -j"$(nproc)" && \
    mv deactivate ../buildroot-fs/bin/
COPY monitor ./monitor/
RUN cd monitor && \
    PATH=../output/host/sbin:$PATH make \
        CC="$CC" \
        EXTRA_BPF_CFLAGS="-I../output/host/include" \
        -j"$(nproc)" && \
    mv execve_monitor ../buildroot-fs/bin/
RUN --mount=type=cache,target=/root/.ccache \
    --mount=type=cache,target=/tmp/buildroot-2025.02/dl \
    make -j"$(nproc)" BR_NO_CHECK_HASH_FOR=linux-6.13.11.tar.xz

FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get -y update && apt-get -y install \
        libfdt1 \
        libglib2.0-0 \
        libpixman-1-0
COPY --from=qemu-9.2.2 /qemu-9.2.2/ /
RUN mkdir /challenge
COPY --from=buildroot-2025.02 \
     /tmp/buildroot-2025.02/output/images/bzImage \
     /tmp/buildroot-2025.02/output/images/rootfs.cpio.zst \
     /challenge/
COPY run-challenge flag /challenge/
WORKDIR /challenge
CMD ["./run-challenge"]
