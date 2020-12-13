#!/usr/bin/env python3
import struct


def main():
    with open('flag.malformed', 'rb') as fp:
        data = fp.read()
    i = 0
    while True:
        if i == len(data):
            break
        cid = data[i:i + 4]
        print(cid)
        i += 4
        clen, = struct.unpack('>I', data[i:i + 4])
        i += 4
        cdata = data[i:i + clen]
        print(cdata)
        i += clen
    with open('flag.djvu', 'wb') as fp:
        fp.write(b'AT&TFORM')
        fp.write(struct.pack('>I', len(data) + 4))
        fp.write(b'DJVM')
        fp.write(data)
    # djvutxt
    # ASIS{_DJVU_f1L3_f0rM4t_iZ_DejaVu}


if __name__ == '__main__':
    main()
