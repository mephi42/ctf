## Smart Contract - simple sol aeg

The first challenge we're given is:

```
Challenge 1/9:
608060405260008060006101000a81548160ff02191690831515021790555034801561002a57600080fd5b5060ec806100396000396000f3006080604052600436106049576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff168063c01b0d4814604e578063ea602fa6146062575b600080fd5b348015605957600080fd5b506060608e565b005b348015606d57600080fd5b50607460aa565b604051808215151515815260200191505060405180910390f35b60016000806101000a81548160ff021916908315150217905550565b60008060009054906101000a900460ff169050905600a165627a7a72305820e4049baf5929e28ad8f5bd556042853a60e8163c4427db9283c4e18c91459fab0029
```

This has to do with [Solidity](https://solidity.readthedocs.io/en/v0.5.12/) -
"an object-oriented, high-level language for implementing smart contracts"
"designed to target the Ethereum Virtual Machine (EVM)". The first step thus is
to obtain a disassembler for EVM.

[pyevmasm](https://github.com/crytic/pyevmasm) looks like a good fit - let's
crack this thing open!

```
#!/usr/bin/env python3
from pyevmasm import disassemble_all
code = bytearray.fromhex(open('sample.bin').read())
for insn in disassemble_all(code):
    print(f'{insn.pc:04x} {insn}')
```

```
0000 PUSH1 0x80
0002 PUSH1 0x40
0004 MSTORE
```

EMV appears to be a stack-based machine, which also has memory. These three
instructions clearly store to memory, but how exactly? Time to find a bytecode
reference, fortunately, there are quite a few:

* https://ethereum.github.io/yellowpaper/paper.pdf, Chapter H.2
* https://solidity.readthedocs.io/en/v0.5.12/assembly.html#opcodes
* https://github.com/crytic/evm-opcodes
* https://ethereum.stackexchange.com/a/120

So, what we have here is `*(int256 *)0x40 = 0x80`, and the stack is empty again.

```
0005 PUSH1 0x0
0007 DUP1
0008 PUSH1 0x0
000a PUSH2 0x100
000d EXP
```

`100 ** 0 = 1` - why not just `PUSH1 1`?. This code is clearly just messing with
us. Stack state: `[0 0 1]`.

```
000e DUP2
000f SLOAD
```

`SLOAD`: "Load word from storage". So, there is memory, and there is storage.
[What's the difference?](https://ethereum.stackexchange.com/questions/1232)
Apparently storage is persistent - makes sense. Stack state: `[0 0 1 s[0]]`.

```
0010 DUP2
0011 PUSH1 0xff
0013 MUL
0014 NOT
0015 AND
```

Nothing unusual. Stack state: `[0 0 1 (s[0] & ~0xff)]`.

```
0016 SWAP1
0017 DUP4
0018 ISZERO
0019 ISZERO
001a MUL
001b OR
001c SWAP1
001d SSTORE
001e POP
```

`s[0] = (s[0] & ~0xff)` - the code above has cleared the least significant byte
of the storage value at index 0, and put it back. Stack state: `[]`.

```
001f CALLVALUE
```

`CALLVALUE`: "Get deposited value by the instruction/transaction responsible
for this execution". This is some sort of argument from our caller. Stack state:
`[arg]`.

```
0020 DUP1
0021 ISZERO
0022 PUSH2 0x2a
0025 JUMPI
0026 PUSH1 0x0
0028 DUP1
0029 REVERT
```

`JUMPI`: "Conditionally alter the program counter" - an "if" statement! If
caller (whatever it is, no idea so far) gave us zero, we proceed. Otherwise we
`REVERT`: "Halt execution reverting state change". Sounds like a bad thing,
let's assume we were given `0` after all. Stack state: `[arg]`.

```
002a JUMPDEST
002b POP
002c PUSH1 0xec
002e DUP1
002f PUSH2 0x39
0032 PUSH1 0x0
0034 CODECOPY
0035 PUSH1 0x0
0037 RETURN
```

`JUMPDEST`: "Mark a valid destination for jumps". Hey, cute - this thingy has
built-in CFI! `CODECOPY`: "Copy code running in current environment to memory".
All in all it was just an initialization step: `memcpy((void *)0, (void*)0x39,
0xec)`. The final stack state is: `[0, 0xec]` - this must describe the copied
region - apparently this will be called the second time. Let's see what's
inside the copied region using `disassemble_all(code[0x39:])`:

```
0000 PUSH1 0x80
0002 PUSH1 0x40
0004 MSTORE
```

Noted. Not sure why the code keeps doing it - is it a moral equivalent of
a function prolog? We'll never know.

```
0005 PUSH1 0x4
0007 CALLDATASIZE
0008 LT
0009 PUSH1 0x49
```
```
0049 JUMPDEST
004a PUSH1 0x0
004c DUP1
004d REVERT
```

So this code is given not merely an integer, but a whopping array. If it's
shorter than 4 bytes, we end up with a `REVERT`.

```
000b JUMPI
000c PUSH1 0x0
000e CALLDATALOAD
000f PUSH29 0x100000000000000000000000000000000000000000000000000000000
002d SWAP1
002e DIV
002f PUSH4 0xffffffff
0034 AND
```

This computes: `(arg[0] / (2 ** 224)) & 0xffffffff`, essentially obtaining 4
most significant bytes of `arg[0]`. This is kind of consistent with the length
check ([EVM is big-endian](https://ethereum.stackexchange.com/a/2344)).

```
0035 DUP1
0036 PUSH4 0xc01b0d48
003b EQ
003c PUSH1 0x4e
003e JUMPI
```

Here the code compares those 4 bytes with a magic constant. This must be the
gist of this challenge: find and analyze such comparisons.

```
003f DUP1
0040 PUSH4 0xea602fa6
0045 EQ
0046 PUSH1 0x62
0048 JUMPI
```

Another comparison. So the first 4 bytes can be one of the two magic constants,
since we don't want to go to `0049` - this is the basic block with `REVERT`,
remember?

Now that it's more or less clear what needs to be done, let's not inspect the
bytecode any further. Finding an input that satisfies all the magic checks is
a job for a symbolic execution tool. While it might be fun implementing one from
scratch, this is not a toy VM and there might be something out there.

Google query "evm symbolic execution" points to multiple projects, the most
mature of which is [Manticore](https://github.com/trailofbits/manticore). The
landing page shows an example of analyzing source Solidity contract with it, but
we have only bytecode.

Googling "manticore bytecode only analysis" gives us a [very nice article](
https://kauri.io/article/9ca9a32cc36340b19fd82de6df12e36c/bytecode-only-analysis-of-evm-smart-contracts
) with a code skeleton. Let's give it a shot!

```
#!/usr/bin/env python3
from manticore.ethereum import ManticoreEVM
code = bytearray.fromhex(open('sample.bin').read())
m = ManticoreEVM()
user_account = m.create_account(balance=1000)
contract_account = m.create_contract(owner=user_account, init=code)
print(f'init ready:      {m.count_ready_states()}')
print(f'init busy:       {m.count_busy_states()}')
print(f'init killed:     {m.count_killed_states()}')
print(f'init terminated: {m.count_terminated_states()}')
```
```
init ready:      1
init busy:       0
init killed:     0
init terminated: 0
```

The initialization part went through successfully. Not sure why the `arg != 0`
branch was not accounted for and we ended up with just one state - maybe
Manticore always passes `0`, but this looks promising. Let's run a transaction
now.

```
symbolic_data = m.make_symbolic_buffer(320, name='symbolic_data')
symbolic_value = m.make_symbolic_value(name='symbolic_value')
tx_address = m.transaction(
    caller=user_account,
    address=contract_account,
    data=symbolic_data,
    value=symbolic_value,
)
print(f'tx ready:      {m.count_ready_states()}')
print(f'tx busy:       {m.count_busy_states()}')
print(f'tx killed:     {m.count_killed_states()}')
print(f'tx terminated: {m.count_terminated_states()}')
```
```
tx ready:      2
tx busy:       0
tx killed:     0
tx terminated: 4
```

That's extremely good. Those two ready states must correspond to a king and a
... how should I call the other thing? Peon? Anyway, let's try to distinguish
them. Memory and stack are volatile, so they must have different storage.

```
for i, state in enumerate(m.ready_states):
    print(f'### STORAGE {i} ###')
    for sindex, svalue in state.platform.get_storage_items(contract_account):
        sindex, = state.concretize(sindex, 'ONE')
        svalue, = state.concretize(svalue, 'ONE')
        print(f'[{sindex}] = {svalue}')
```
```
### STORAGE 0 ###
[0] = 0
### STORAGE 1 ###
[0] = 1
[0] = 0
```

This looks like a log, which contains all stores, with the most recent ones
coming first. The state #1 has one extra store - this must be the king. So,
what should I send to the server - the data or the value? [Turns out](
https://ethereum.stackexchange.com/questions/1990), value is the amount of $$$
to transfer, and data is a free-format input parameter. Obviously we want the
latter. Let's send it to server:

```
data, = state.concretize(symbolic_data, 'ONE')
print(data)
```
```
### DATA 1 ###
b'\xc0\x1b\rH\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
Challenge 2/9:
```

It has a magic constant from earlier. And the server likes it. Woohoo!

Well, not so fast. The second challenge takes way more time to complete, and the
server resets the connection. Checking with `cProfile` shows that we spend all
the time in `_recv`, which most likely means we wait for the solver to give us
answers. That's pretty ugly, but maybe we could tune the symbolic execution to
issue less or smaller queries?

Let's hook into `_send` and `_recv` (in [`manticore/core/smtlib/solver.py`](
https://github.com/trailofbits/manticore/blob/0.3.1/manticore/core/smtlib/solver.py#L280
)) and see which queries give z3 a hard time:

```
    def _send(self, cmd: str):
        try:
            print(f"{cmd}")
```
```
    def _recv(self) -> str:
        t0 = time.time()
        ...
        print(f"DONE {time.time() - t0}")
```

This one takes 8 seconds, and there are quite a few more like it:

```
(set-logic QF_AUFBV)
(set-option :global-decls false)
(declare-fun symbolic_data () (Array (_ BitVec 256) (_ BitVec 8)))
(declare-fun B () Bool)
(declare-fun a_112 () (_ BitVec 8))(assert (= a_112 (select symbolic_data #x0000000000000000000000000000000000000000000000000000000000000004)))
(declare-fun a_113 () (_ BitVec 8))(assert (= a_113 (select symbolic_data #x0000000000000000000000000000000000000000000000000000000000000005)))
(declare-fun a_114 () (_ BitVec 8))(assert (= a_114 (select symbolic_data #x0000000000000000000000000000000000000000000000000000000000000006)))
(declare-fun a_115 () (_ BitVec 8))(assert (= a_115 (select symbolic_data #x0000000000000000000000000000000000000000000000000000000000000007)))
(declare-fun a_116 () (_ BitVec 8))(assert (= a_116 (select symbolic_data #x0000000000000000000000000000000000000000000000000000000000000008)))
(declare-fun a_117 () (_ BitVec 8))(assert (= a_117 (select symbolic_data #x0000000000000000000000000000000000000000000000000000000000000009)))
(declare-fun a_118 () (_ BitVec 8))(assert (= a_118 (select symbolic_data #x000000000000000000000000000000000000000000000000000000000000000a)))
(declare-fun a_119 () (_ BitVec 8))(assert (= a_119 (select symbolic_data #x000000000000000000000000000000000000000000000000000000000000000b)))
(declare-fun a_120 () (_ BitVec 8))(assert (= a_120 (select symbolic_data #x000000000000000000000000000000000000000000000000000000000000000c)))
(declare-fun a_121 () (_ BitVec 8))(assert (= a_121 (select symbolic_data #x000000000000000000000000000000000000000000000000000000000000000d)))
(declare-fun a_122 () (_ BitVec 8))(assert (= a_122 (select symbolic_data #x000000000000000000000000000000000000000000000000000000000000000e)))
(declare-fun a_123 () (_ BitVec 8))(assert (= a_123 (select symbolic_data #x000000000000000000000000000000000000000000000000000000000000000f)))
(declare-fun a_124 () (_ BitVec 8))(assert (= a_124 (select symbolic_data #x0000000000000000000000000000000000000000000000000000000000000010)))
(declare-fun a_125 () (_ BitVec 8))(assert (= a_125 (select symbolic_data #x0000000000000000000000000000000000000000000000000000000000000011)))
(declare-fun a_126 () (_ BitVec 8))(assert (= a_126 (select symbolic_data #x0000000000000000000000000000000000000000000000000000000000000012)))
(declare-fun a_127 () (_ BitVec 8))(assert (= a_127 (select symbolic_data #x0000000000000000000000000000000000000000000000000000000000000013)))
(declare-fun a_128 () (_ BitVec 8))(assert (= a_128 (select symbolic_data #x0000000000000000000000000000000000000000000000000000000000000014)))
(declare-fun a_129 () (_ BitVec 8))(assert (= a_129 (select symbolic_data #x0000000000000000000000000000000000000000000000000000000000000015)))
(declare-fun a_130 () (_ BitVec 8))(assert (= a_130 (select symbolic_data #x0000000000000000000000000000000000000000000000000000000000000016)))
(declare-fun a_131 () (_ BitVec 8))(assert (= a_131 (select symbolic_data #x0000000000000000000000000000000000000000000000000000000000000017)))
(declare-fun a_132 () (_ BitVec 8))(assert (= a_132 (select symbolic_data #x0000000000000000000000000000000000000000000000000000000000000018)))
(declare-fun a_133 () (_ BitVec 8))(assert (= a_133 (select symbolic_data #x0000000000000000000000000000000000000000000000000000000000000019)))
(declare-fun a_134 () (_ BitVec 8))(assert (= a_134 (select symbolic_data #x000000000000000000000000000000000000000000000000000000000000001a)))
(declare-fun a_135 () (_ BitVec 8))(assert (= a_135 (select symbolic_data #x000000000000000000000000000000000000000000000000000000000000001b)))
(declare-fun a_136 () (_ BitVec 8))(assert (= a_136 (select symbolic_data #x000000000000000000000000000000000000000000000000000000000000001c)))
(declare-fun a_137 () (_ BitVec 8))(assert (= a_137 (select symbolic_data #x000000000000000000000000000000000000000000000000000000000000001d)))
(declare-fun a_138 () (_ BitVec 8))(assert (= a_138 (select symbolic_data #x000000000000000000000000000000000000000000000000000000000000001e)))
(declare-fun a_139 () (_ BitVec 8))(assert (= a_139 (select symbolic_data #x000000000000000000000000000000000000000000000000000000000000001f)))
(declare-fun a_140 () (_ BitVec 8))(assert (= a_140 (select symbolic_data #x0000000000000000000000000000000000000000000000000000000000000020)))
(declare-fun a_141 () (_ BitVec 8))(assert (= a_141 (select symbolic_data #x0000000000000000000000000000000000000000000000000000000000000021)))
(declare-fun a_142 () (_ BitVec 8))(assert (= a_142 (select symbolic_data #x0000000000000000000000000000000000000000000000000000000000000022)))
(declare-fun a_143 () (_ BitVec 8))(assert (= a_143 (select symbolic_data #x0000000000000000000000000000000000000000000000000000000000000023)))
(declare-fun a_144 () (_ BitVec 256))(assert (= a_144 #x0000000000000000000000000000000000000000000000000000000000000064))
(declare-fun a_145 () (_ BitVec 256))(assert (= a_145 (concat a_112 a_113 a_114 a_115 a_116 a_117 a_118 a_119 a_120 a_121 a_122 a_123 a_124 a_125 a_126 a_127 a_128 a_129 a_130 a_131 a_132 a_133 a_134 a_135 a_136 a_137 a_138 a_139 a_140 a_141 a_142 a_143)))
(declare-fun a_146 () (_ BitVec 256))(assert (= a_146 (bvsub a_144 a_145)))
(declare-fun a_147 () (_ BitVec 256))(assert (= a_147 #x0000000000000000000000000000000000000000000000000000000000031dd6))
(declare-fun a_148 () Bool)(assert (= a_148 (bvugt a_146 a_147)))
(declare-fun a_149 () (_ BitVec 256))(assert (= a_149 #x0000000000000000000000000000000000000000000000000000000000000001))
(declare-fun a_150 () (_ BitVec 256))(assert (= a_150 #x0000000000000000000000000000000000000000000000000000000000000000))
(declare-fun a_151 () (_ BitVec 256))(assert (= a_151 (ite a_148 a_149 a_150)))
(declare-fun a_152 () (_ BitVec 256))(assert (= a_152 #x0000000000000000000000000000000000000000000000000000000000000000))
(declare-fun a_153 () Bool)(assert (= a_153 (= a_151 a_152)))
(declare-fun a_154 () (_ BitVec 256))(assert (= a_154 #x0000000000000000000000000000000000000000000000000000000000000001))
(declare-fun a_155 () (_ BitVec 256))(assert (= a_155 #x0000000000000000000000000000000000000000000000000000000000000000))
(declare-fun a_156 () (_ BitVec 256))(assert (= a_156 (ite a_153 a_154 a_155)))
(declare-fun a_157 () (_ BitVec 256))(assert (= a_157 #x0000000000000000000000000000000000000000000000000000000000000000))
(declare-fun a_158 () Bool)(assert (= a_158 (= a_156 a_157)))
(declare-fun a_159 () Bool)(assert (= a_159 (not a_158)))
(declare-fun a_160 () (_ BitVec 256))(assert (= a_160 #x0000000000000000000000000000000000000000000000000000000000000128))
(declare-fun a_161 () (_ BitVec 256))(assert (= a_161 #x00000000000000000000000000000000000000000000000000000000000000e1))
(declare-fun a_162 () (_ BitVec 256))(assert (= a_162 (ite a_159 a_160 a_161)))
(declare-fun a_163 () (_ BitVec 256))(assert (= a_163 #x00000000000000000000000000000000000000000000000000000000000000e1))
(declare-fun a_164 () (_ BitVec 256))(assert (= a_164 (bvsub a_144 a_145)))
(declare-fun a_165 () (_ BitVec 256))(assert (= a_165 #x0000000000000000000000000000000000000000000000000000000000031ddd))
(declare-fun a_166 () Bool)(assert (= a_166 (bvult a_164 a_165)))
(declare-fun a_167 () (_ BitVec 256))(assert (= a_167 #x0000000000000000000000000000000000000000000000000000000000000001))
(declare-fun a_168 () (_ BitVec 256))(assert (= a_168 #x0000000000000000000000000000000000000000000000000000000000000000))
(declare-fun a_169 () (_ BitVec 256))(assert (= a_169 (ite a_166 a_167 a_168)))
(declare-fun a_170 () (_ BitVec 256))(assert (= a_170 #x0000000000000000000000000000000000000000000000000000000000000000))
(declare-fun a_171 () Bool)(assert (= a_171 (= a_169 a_170)))
(declare-fun a_172 () (_ BitVec 256))(assert (= a_172 #x0000000000000000000000000000000000000000000000000000000000000001))
(declare-fun a_173 () (_ BitVec 256))(assert (= a_173 #x0000000000000000000000000000000000000000000000000000000000000000))
(declare-fun a_174 () (_ BitVec 256))(assert (= a_174 (ite a_171 a_172 a_173)))
(declare-fun a_175 () (_ BitVec 256))(assert (= a_175 #x0000000000000000000000000000000000000000000000000000000000000000))
(declare-fun a_176 () Bool)(assert (= a_176 (= a_174 a_175)))
(declare-fun a_177 () Bool)(assert (= a_177 (not a_176)))
(declare-fun a_178 () (_ BitVec 256))(assert (= a_178 #x000000000000000000000000000000000000000000000000000000000000010c))
(declare-fun a_179 () (_ BitVec 256))(assert (= a_179 #x00000000000000000000000000000000000000000000000000000000000000ee))
(declare-fun a_180 () (_ BitVec 256))(assert (= a_180 (ite a_177 a_178 a_179)))
(declare-fun a_181 () (_ BitVec 256))(assert (= a_181 #x00000000000000000000000000000000000000000000000000000000000000ee))
(declare-fun a_182 () (_ BitVec 8))(assert (= a_182 (select symbolic_data #x0000000000000000000000000000000000000000000000000000000000000000)))
(declare-fun a_183 () (_ BitVec 8))(assert (= a_183 (select symbolic_data #x0000000000000000000000000000000000000000000000000000000000000001)))
(declare-fun a_184 () (_ BitVec 8))(assert (= a_184 (select symbolic_data #x0000000000000000000000000000000000000000000000000000000000000002)))
(declare-fun a_185 () (_ BitVec 8))(assert (= a_185 (select symbolic_data #x0000000000000000000000000000000000000000000000000000000000000003)))
(declare-fun a_186 () (_ BitVec 8))(assert (= a_186 (select symbolic_data #x0000000000000000000000000000000000000000000000000000000000000004)))
(declare-fun a_187 () (_ BitVec 8))(assert (= a_187 (select symbolic_data #x0000000000000000000000000000000000000000000000000000000000000005)))
(declare-fun a_188 () (_ BitVec 8))(assert (= a_188 (select symbolic_data #x0000000000000000000000000000000000000000000000000000000000000006)))
(declare-fun a_189 () (_ BitVec 8))(assert (= a_189 (select symbolic_data #x0000000000000000000000000000000000000000000000000000000000000007)))
(declare-fun a_190 () (_ BitVec 8))(assert (= a_190 (select symbolic_data #x0000000000000000000000000000000000000000000000000000000000000008)))
(declare-fun a_191 () (_ BitVec 8))(assert (= a_191 (select symbolic_data #x0000000000000000000000000000000000000000000000000000000000000009)))
(declare-fun a_192 () (_ BitVec 8))(assert (= a_192 (select symbolic_data #x000000000000000000000000000000000000000000000000000000000000000a)))
(declare-fun a_193 () (_ BitVec 8))(assert (= a_193 (select symbolic_data #x000000000000000000000000000000000000000000000000000000000000000b)))
(declare-fun a_194 () (_ BitVec 8))(assert (= a_194 (select symbolic_data #x000000000000000000000000000000000000000000000000000000000000000c)))
(declare-fun a_195 () (_ BitVec 8))(assert (= a_195 (select symbolic_data #x000000000000000000000000000000000000000000000000000000000000000d)))
(declare-fun a_196 () (_ BitVec 8))(assert (= a_196 (select symbolic_data #x000000000000000000000000000000000000000000000000000000000000000e)))
(declare-fun a_197 () (_ BitVec 8))(assert (= a_197 (select symbolic_data #x000000000000000000000000000000000000000000000000000000000000000f)))
(declare-fun a_198 () (_ BitVec 8))(assert (= a_198 (select symbolic_data #x0000000000000000000000000000000000000000000000000000000000000010)))
(declare-fun a_199 () (_ BitVec 8))(assert (= a_199 (select symbolic_data #x0000000000000000000000000000000000000000000000000000000000000011)))
(declare-fun a_200 () (_ BitVec 8))(assert (= a_200 (select symbolic_data #x0000000000000000000000000000000000000000000000000000000000000012)))
(declare-fun a_201 () (_ BitVec 8))(assert (= a_201 (select symbolic_data #x0000000000000000000000000000000000000000000000000000000000000013)))
(declare-fun a_202 () (_ BitVec 8))(assert (= a_202 (select symbolic_data #x0000000000000000000000000000000000000000000000000000000000000014)))
(declare-fun a_203 () (_ BitVec 8))(assert (= a_203 (select symbolic_data #x0000000000000000000000000000000000000000000000000000000000000015)))
(declare-fun a_204 () (_ BitVec 8))(assert (= a_204 (select symbolic_data #x0000000000000000000000000000000000000000000000000000000000000016)))
(declare-fun a_205 () (_ BitVec 8))(assert (= a_205 (select symbolic_data #x0000000000000000000000000000000000000000000000000000000000000017)))
(declare-fun a_206 () (_ BitVec 8))(assert (= a_206 (select symbolic_data #x0000000000000000000000000000000000000000000000000000000000000018)))
(declare-fun a_207 () (_ BitVec 8))(assert (= a_207 (select symbolic_data #x0000000000000000000000000000000000000000000000000000000000000019)))
(declare-fun a_208 () (_ BitVec 8))(assert (= a_208 (select symbolic_data #x000000000000000000000000000000000000000000000000000000000000001a)))
(declare-fun a_209 () (_ BitVec 8))(assert (= a_209 (select symbolic_data #x000000000000000000000000000000000000000000000000000000000000001b)))
(declare-fun a_210 () (_ BitVec 8))(assert (= a_210 (select symbolic_data #x000000000000000000000000000000000000000000000000000000000000001c)))
(declare-fun a_211 () (_ BitVec 8))(assert (= a_211 (select symbolic_data #x000000000000000000000000000000000000000000000000000000000000001d)))
(declare-fun a_212 () (_ BitVec 8))(assert (= a_212 (select symbolic_data #x000000000000000000000000000000000000000000000000000000000000001e)))
(declare-fun a_213 () (_ BitVec 8))(assert (= a_213 (select symbolic_data #x000000000000000000000000000000000000000000000000000000000000001f)))
(declare-fun a_214 () (_ BitVec 256))(assert (= a_214 (concat a_182 a_183 a_184 a_185 a_186 a_187 a_188 a_189 a_190 a_191 a_192 a_193 a_194 a_195 a_196 a_197 a_198 a_199 a_200 a_201 a_202 a_203 a_204 a_205 a_206 a_207 a_208 a_209 a_210 a_211 a_212 a_213)))
(declare-fun a_215 () (_ BitVec 256))(assert (= a_215 #x0000000100000000000000000000000000000000000000000000000000000000))
(declare-fun a_216 () (_ BitVec 256))(assert (= a_216 (bvudiv a_214 a_215)))
(declare-fun a_217 () (_ BitVec 256))(assert (= a_217 #x00000000000000000000000000000000000000000000000000000000ffffffff))
(declare-fun a_218 () (_ BitVec 256))(assert (= a_218 (bvand a_216 a_217)))
(declare-fun a_219 () (_ BitVec 256))(assert (= a_219 #x00000000000000000000000000000000000000000000000000000000f1252860))
(declare-fun a_220 () Bool)(assert (= a_220 (= a_218 a_219)))
(declare-fun a_221 () (_ BitVec 256))(assert (= a_221 #x0000000000000000000000000000000000000000000000000000000000000001))
(declare-fun a_222 () (_ BitVec 256))(assert (= a_222 #x0000000000000000000000000000000000000000000000000000000000000000))
(declare-fun a_223 () (_ BitVec 256))(assert (= a_223 (ite a_220 a_221 a_222)))
(declare-fun a_224 () (_ BitVec 256))(assert (= a_224 #x0000000000000000000000000000000000000000000000000000000000000000))
(declare-fun a_225 () Bool)(assert (= a_225 (= a_223 a_224)))
(declare-fun a_226 () Bool)(assert (= a_226 (not a_225)))
(declare-fun a_227 () (_ BitVec 256))(assert (= a_227 #x0000000000000000000000000000000000000000000000000000000000000080))
(declare-fun a_228 () (_ BitVec 256))(assert (= a_228 #x000000000000000000000000000000000000000000000000000000000000004c))
(declare-fun a_229 () (_ BitVec 256))(assert (= a_229 (ite a_226 a_227 a_228)))
(declare-fun a_230 () (_ BitVec 256))(assert (= a_230 #x0000000000000000000000000000000000000000000000000000000000000080))
(declare-fun a_231 () (_ BitVec 256))(assert (= a_231 (ite a_171 a_172 a_173)))
(declare-fun a_232 () (_ BitVec 256))(assert (= a_232 #x0000000000000000000000000000000000000000000000000000000000000000))
(declare-fun a_233 () Bool)(assert (= a_233 (= a_231 a_232)))
(declare-fun a_234 () Bool)(assert (= a_234 (not a_233)))
(declare-fun a_235 () (_ BitVec 256))(assert (= a_235 (bvand a_216 a_217)))
(declare-fun a_236 () (_ BitVec 256))(assert (= a_236 #x00000000000000000000000000000000000000000000000000000000ea602fa6))
(declare-fun a_237 () Bool)(assert (= a_237 (= a_235 a_236)))
(declare-fun a_238 () (_ BitVec 256))(assert (= a_238 #x0000000000000000000000000000000000000000000000000000000000000001))
(declare-fun a_239 () (_ BitVec 256))(assert (= a_239 #x0000000000000000000000000000000000000000000000000000000000000000))
(declare-fun a_240 () (_ BitVec 256))(assert (= a_240 (ite a_237 a_238 a_239)))
(declare-fun a_241 () (_ BitVec 256))(assert (= a_241 #x0000000000000000000000000000000000000000000000000000000000000000))
(declare-fun a_242 () Bool)(assert (= a_242 (= a_240 a_241)))
(declare-fun a_243 () Bool)(assert (= a_243 (not a_242)))
(declare-fun a_244 () (_ BitVec 256))(assert (= a_244 #x0000000000000000000000000000000000000000000000000000000000000051))
(declare-fun a_245 () (_ BitVec 256))(assert (= a_245 #x0000000000000000000000000000000000000000000000000000000000000041))
(declare-fun a_246 () (_ BitVec 256))(assert (= a_246 (ite a_243 a_244 a_245)))
(declare-fun a_247 () (_ BitVec 256))(assert (= a_247 #x0000000000000000000000000000000000000000000000000000000000000041))
(assert (= a_246 a_247))
(assert (= B a_234))
(assert (= a_229 a_230))
(assert (= a_180 a_181))
(assert (= a_162 a_163))
(check-sat)
```

While longish and repetitive, it does not look too onerous. Giving it to `z3`
command-like tool results in a similar run time:

```
$ time -p z3 slow.z3
sat
real 8,70
```

When ending up in an apparent dead-end like this one, googling never hurts, does
it?

"z3 slow query", on the [first hit](https://github.com/Z3Prover/z3/issues/1602)
the advice is: use `(check-sat-using smt)`.

```
$ time -p z3 slow.z3
sat
real 0,07
```

Now so slow anymore, huh? Let's patch manticore:

```
    def _is_sat(self) -> bool:
        ...
        #self._send("(check-sat)")
        self._send("(check-sat-using smt)")
```
```
$ time -p python3 ./solve.py
real 4,59
```

That's acceptable. This indeed does the trick and allows us to solve all 9
challenges and obtain the coveted flag.
