#!/bin/sh
/usr/bin/qemu-system-mipsel \
-kernel ./vmlinux \
-initrd ./rootfs.img.gz \
-append 'root=/dev/ram console=ttyS0 rw physmap.enabled=0 noapic quiet log_level=0 rdinit=/init.dbg' \
-m 256M \
-nographic \
-monitor /dev/null \
-no-reboot \
-nic tap \
-s \
2>/dev/null
