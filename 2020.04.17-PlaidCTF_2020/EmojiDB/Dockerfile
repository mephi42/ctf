FROM ubuntu:18.04

RUN apt-get update
RUN apt-get install -y xinetd
RUN apt-get install -y language-pack-en
RUN apt-get install -y gdb
RUN apt-get install -y valgrind
RUN apt-get install -y electric-fence
RUN apt-get install -y xterm
RUN apt-get install -y python3

RUN apt-get -y update
RUN apt-get -y install python3 python3-pip python3-dev git libssl-dev libffi-dev build-essential
RUN python3 -m pip install --upgrade pip
RUN python3 -m pip install --upgrade git+https://github.com/Gallopsled/pwntools.git@dev

RUN sed -i 's/# deb-src/deb-src/g' /etc/apt/sources.list
RUN apt-get -y update

RUN useradd -m ctf

COPY bin /home/ctf
COPY emojidb.xinetd /etc/xinetd.d/emojidb

RUN chown -R root:root /home/ctf
EXPOSE 9876
CMD ["/home/ctf/start.sh"]
