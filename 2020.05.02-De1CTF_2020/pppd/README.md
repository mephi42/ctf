# pppd

# Summary

We need to pwn [pppd](https://github.com/paulusmack/ppp) using [CVE-2020-8597](
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-8597) on MIPS. Nuff
said.

# Analysis

We are given a MIPS VM (vmlinux + initramfs), which contains pppd v2.4.7. pppd
is started via inittab as follows:

```
ttyS0::sysinit:/pppd auth local lock defaultroute nodetach 172.16.1.1:172.16.1.2 ms-dns 8.8.8.8 require-eap lcp-max-configure 100
```

The bug in question is fixed by
https://github.com/paulusmack/ppp/commit/8d7970b8f3db, which shows that if we
manage to trigger `eap_request()`, due to totally defunct bounds check we can
supply a large `rhostname`, overwrite saved `ra` and get pc control.

The binary is compiled without any mitigations whatsoever, most importantly:
no ASLR and no W^X.

# Debugging

First order of business is to establish some kind of debugging setup. The
supplied VM lacks debugging tools, but I have a [handy script](
https://github.com/mephi42/initramfs-wrap) that adds strace, gdb and even
valgrind.

Ok, the tools are available, but how to apply them to conveniently debug the
exploit, given that exploitation process ties up the only TTY? Over the network,
of course! The supplied kernel is not stripped, as is sometimes the case during
CTFs, and network Just Works&trade; by just adding `-nic tap` to the provided
[start.sh](start-dbg.sh) and injecting our own [init](init.dbg) that issues a
bunch of `ip` commands before `exec()`ing the original one.

Two other modifications to qemu arguments are: `-m 256M` (maximum QEMU MIPS
supports, believe it or not :-/) and `-s` (yes, for kernel debugging - we'll get
to that).

Another thing that the injected init does is starting a bind shell with socat in
the background. I didn't try ssh, because I thought it won't fit: the available
memory must accommodate the kernel and both the compressed and uncompressed
initramfs at a certain point in time.

There are two QoL problems with the bind shell: gdb takes ages to start in a VM,
and Ctrl+C just kills the connection instead of interrupting the debugged
program. Both of them can be solved by starting `gdbserver` over the bind shell,
and connecting to it using `gdb-multiarch` from the host.

That's how debugging setup looked like at the end:

Step 0 - extract initramfs, needed for gdb:

```
rootfs$ gunzip <../rootfs.img | cpio -idv
```

Step 1 - needed because `-nic tap` requires root, and I didn't really want to
run exploit as root. So I replicated orgas' setup instead:

```
$ sudo socat TCP-LISTEN:8848,reuseaddr,fork EXEC:./start-dbg.sh
```

Step 2 - run exploit. This cleans up old VMs and triggers startup of a new one.
In the exploit I added `pause()` calls before critical actions, so that I would
have some time to attach.

```
$ (sudo killall qemu-system-mipsel && sleep 1) ; ./pwnit.py LOCAL DEBUG
```

Step 3 - configure host tap ip and start gdbserver:

```
$ sudo ip addr add 192.168.33.1/24 dev tap0 ; nc 192.168.33.2 4444
# gdbserver --multi --attach 0.0.0.0:5555 $(pidof pppd)
```

Step 4 - attach and optionally set some breakpoints right away:

```
$ gdb-multiarch -ex 'set sysroot rootfs' \
                -ex 'target remote 192.168.33.2:5555' \
                -ex 'b *0x430198' \
                -ex 'c' \
                rootfs/pppd
```

Phew, that was very involved, and is only as convenient as it gets. Still the
effort paid off very handsomely and will most likely be usable for similar
challenges in the future.

# Existing exploit

[There is something to try out](
https://dl.packetstormsecurity.net/2003-exploits/CVE-2020-8597.py.txt), cool!
The exploit looks neutered (to protect the guilty and innocent alike against
script kiddies?) - there must be more than 256 `A`s, and it's just DoS anyway -
there is no payload, but it's a good start.

Ethernet headers must be stripped first though; I used a very lazy approach and
ran the exploit against localhost, capturing the traffic in wireshark. It has
indeed shown me the EAP request, which I copy-pasted, adjusted the number of
`A`s and length fields (using [EAP RFC](https://tools.ietf.org/html/rfc2284) a
a reference) and replayed against my instance. Aaand nothing - the server did
not crash.

# Talking to pppd

Surely I messed up the packet structure somehow - this can be easily resolved by
setting a breakpoint on [`get_input()`](
https://github.com/paulusmack/ppp/blob/ppp-2.4.7/pppd/main.c#L1019) function and
single-stepping to see which of the checks fails. Aaand nothing again - my
packet is not even seen by pppd. Time to start using the brain, for better or
worse.

First of all, PPP packets can be wrapped in multiple protocols - the existing
exploit uses Ethernet, and the challenge most likely uses some kind of serial
line. Correlating the packets that pppd sends when it starts with [PPP RFC](
https://tools.ietf.org/html/rfc1331) confirms this: the first two bytes are
`0x7e 0xff`, which corresponds to constant "flag" and "address" fields.

The third byte ("control") does not match though: it's `0x7d` instead of the
expected `0x3`. Linux sources quite unhelpfully provide the following hint:

```
#define	PPP_ESCAPE	0x7d	/* Asynchronous Control Escape */
```

So.. it's some kind of undocumented "control" value that Linux uses? Well, no.
After some mucking around I realized I need to use the information from Appendix
A.: Asynchronous HDLC of the PPP RFC (the linux driver is called
[`ppp_async.c`](
https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/drivers/net/ppp/ppp_async.c?h=v4.11.3
), so this matches quite nicely). It defines the escaping mechanism: values less
than `0x20` as well as `0x7d` and `0x7e` are escaped by prepending `0x7d` byte
and xoring the original byte with `0x20`. Now it begins to make sense: in
packets that pppd sends `0x7d` on the third position is followed by `0x23`, so
this is the correct "control" value.

Ok, so it's clear that in the DoS attempt the encapsulation was messed up, but
where is the packet? Reading the linux driver further brings us to the
[following function](
https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/drivers/net/ppp/ppp_async.c?h=v4.11.3#n831
), which explains everything:

```
/* Called when the tty driver has data for us. Runs parallel with the
   other ldisc functions but will not be re-entered */

static void
ppp_async_input(struct asyncppp *ap, const unsigned char *buf,
```

So the transfer of data between PPP and TTY devices happens not in pppd, but in
the kernel! There must be some ioctls to set that up, right? [Sure there are!](
https://github.com/paulusmack/ppp/blob/ppp-2.4.7/pppd/sys-linux.c#L394)

Okay, so the kernel needs to be made happy first. It would be handy to
single-step through the kernel code that handles packets, which can be achieved
by attaching to qemu gdbserver that was enabled earlier with `-s` as follows:

```
gdb-multiarch -ex 'target remote localhost:1234' ./vmlinux
```

and setting breakpoints (symbols are not stripped, and the kernel version is
known - `v4.11.3`, so asm can be correlated with the source code).

There are three kind of sort of crazy things in PPP RFC that must be taken into
account:

* Each packet must start and end with the `0x7e` flag. This and this alone
  defines its length.
* Escaping. What needs to be escaped are: bytes with small values (for whatever
  reason), as well as escape symbol itself and flags (reasonable).
* FCS checksum. I call it crazy, because of the checking procedure: instead of
  computing the checksum of the original data and comparing the result with the
  checksum field, instead the checksum of the original data AND the checksum
  field is computed and compared with the constant value. Mathematically this is
  reasonable - why not?, but I have not seen anything like this before.

# LCP state machine

Implementing the above is indeed enough to convince the kernel to pass the
packet to pppd. However, again, no luck - pppd does not crash. Fortunately,
single-stepping works now, so the brain can be switched back to the energy
saving mode.

The reason EAP packet doesn't get far enough is that the [following check](
https://github.com/paulusmack/ppp/blob/ppp-2.4.7/pppd/main.c#L1062) fails:

```
    /*
     * Toss all non-LCP packets unless LCP is OPEN.
     */
    if (protocol != PPP_LCP && lcp_fsm[0].state != OPENED) {
```

So some kind of LCP handshake is needed before interesting packets can be sent.
By correlating section 5.1. State Diagram with `lcp_fsm`-related source code,
I could come up with the following sequence: recv Configure-Request (that's
what startup packets actually are), send Configure-Ack, send Configure-Request
(curiously, pppd rejects such packets if they contain options it previously
sent - probably has to do with options being applicable to each direction
individually - so it's better to just make it empty), recv Configure-Ack.

And send EAP request. And, finally, KABOOM! SIGSEGV trying to execute code at
address `0x414141`. pc control achieved.

# Exploitation

I thought I could make the challenge even more interesting by using ROP
(well, no - in reality, I just forgot there was no W^X ;)), but this turned out
to be an exercise in futility: I managed to call `device_script(a0="sh",
a1=STDIN_FILENO, a2=STDOUT_FILENO, a3=0)`, but I could not talk to my shell,
because the kernel was still sitting in the middle and of course it did not like
my `cat flag` command or anything that the shell would've sent back had it
received it.

What was missing was a [`tty_disestablish_ppp(0)`](
https://github.com/paulusmack/ppp/blob/ppp-2.4.7/pppd/sys-linux.c#L545) call to
undo the unholy TTY/PPP union, however, I could not find any gadgets to call
a function and then return to a controlled location (something like
`lw ra, X(sp); jr Y`, where I control `Y`).

In desperation I finally remembered about W|X, and the rest was easy: the
packets are stored in the global variable, so I just needed to put the shellcode
that does `tty_disestablish_ppp`+`execl` somewhere in the packet and overwrite
the return address with the address of that buffer.

[That worked](pwnit.py).

# Flag

`De1CTF{PpPd_5tackOverf1ow_1s_1ntersT1ng}`
