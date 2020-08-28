#!/usr/bin/env python3
import struct
import subprocess

zip_data = open('corrupted_project', 'rb').read()
compressed_size, uncompressed_size, name_length, extra_length = \
    struct.unpack('<IIHH', zip_data[0x12:0x1e])
assert zip_data[0x1e:0x1e + name_length] == b'project-files.zip'

bzip_offset = 0x1e + name_length + extra_length
bzip_data = bytearray(zip_data[bzip_offset:bzip_offset + compressed_size])
bzip_data[2:3] = b'h'
bzip_data[4:10] = b'\x31\x41\x59\x26\x53\x59'
assert bzip_data.startswith(b'BZ')
with open('project-files.zip.bz2', 'wb') as fp:
    fp.write(bzip_data)
subprocess.check_call(['bzip2', '-df', 'project-files.zip.bz2'])
subprocess.check_call(['unzip', '-o', 'project-files.zip'])

png_data = bytearray(open('project-files/project-notes-1.png', 'rb').read())
png_data[0:4] = b'\x89\x50\x4e\x47'  # magic
png_data[0x8b:0x8f] = b'\x9e\xde\xd4\x53'  # crc
png_data[-8:] = b'IEND\xae\x42\x60\x82'  # magic, crc
with open('flag.png', 'wb') as fp:
    fp.write(png_data)
