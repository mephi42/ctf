FROM ubuntu:20.04 as qemu-7.0.0
ENV DEBIAN_FRONTEND=noninteractive
RUN sed -i 's/^# deb-src /deb-src /g' /etc/apt/sources.list
RUN apt-get -y update && apt-get -y install \
        ninja-build \
        tar \
        wget \
        xz-utils
RUN apt-get -y update && apt-get -y build-dep \
        qemu-system-s390x
WORKDIR /tmp
COPY Makefile.qemu .
RUN make -f Makefile.qemu -j"$(nproc)" install

FROM ubuntu:20.04 as buildroot-2022.05-for-participants
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get -y update && apt-get -y install \
        bc \
        cpio \
        file \
        g++ \
        gcc \
        git \
        make \
        python3 \
        rsync \
        tar \
        unzip \
        wget \
        xz-utils
WORKDIR /tmp
RUN wget https://buildroot.org/downloads/buildroot-2022.05.tar.xz
RUN tar xvJf buildroot-2022.05.tar.xz
WORKDIR /tmp/buildroot-2022.05
COPY buildroot-2022.05 ./
RUN make -j"$(nproc)" olddefconfig
RUN make -j"$(nproc)"

FROM buildroot-2022.05-for-participants as buildroot-2022.05-for-organizators
ARG flag
RUN echo ${flag} >buildroot-fs/flag
RUN make -j"$(nproc)"

FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get -y update && apt-get -y install \
        libfdt1 \
        libglib2.0-0 \
        libpixman-1-0
COPY --from=qemu-7.0.0 /qemu-7.0.0/ /
COPY --from=buildroot-2022.05-for-organizators /tmp/buildroot-2022.05/output/images/ /
COPY run /
CMD ["./run"]
