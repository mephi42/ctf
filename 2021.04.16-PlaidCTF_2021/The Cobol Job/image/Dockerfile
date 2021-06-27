FROM ubuntu:18.04

# RUN apt update && apt install -y open-cobol
RUN apt update && apt install -y open-cobol \
    python3 python3-pip python3-dev git libssl-dev libffi-dev build-essential \
    curl gdb valgrind xterm
RUN python3 -m pip install --upgrade pip
RUN python3 -m pip install --upgrade git+https://github.com/Gallopsled/pwntools.git

RUN adduser opencbl
RUN adduser --disabled-login flag
COPY chall /home/opencbl/chall
COPY flag.txt /flag.txt
COPY freader /freader

RUN chmod 0550 /home/opencbl/chall
RUN chmod 0400 /flag.txt
RUN chmod 0550 /freader

RUN chown opencbl:opencbl /home/opencbl/chall
RUN chown flag:flag /flag.txt
RUN chown flag:opencbl /freader
RUN chmod u+s /freader

USER opencbl
WORKDIR /home/opencbl
# CMD ["timeout", "-k", "60", "60", "./chall"]
RUN bash -c "$(curl -fsSL http://gef.blah.cat/sh)"
