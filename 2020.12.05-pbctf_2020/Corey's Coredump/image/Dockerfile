FROM debian:bullseye
COPY sources.list /etc/apt/
RUN apt-get -y update
RUN apt-get -y install dpkg-dev
RUN apt-get -y build-dep valgrind
RUN apt-get -y install libc6-dbg
RUN apt-get -y install procps
RUN apt-get -y install gdb
RUN apt-get -y install strace
RUN apt-get -y install python3
RUN apt-get -y install python3-pip
RUN apt-get -y install less
