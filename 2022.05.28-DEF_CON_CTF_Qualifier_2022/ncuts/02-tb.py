from collections import defaultdict
import re
import sys
from glob import glob
import random
import z3
import json
from json.decoder import JSONDecodeError
import os

from elftools.elf.elffile import ELFFile

ASM_RE = re.compile(r"^0x([0-9a-f]+):(.*)")


class InAsm:
    def __init__(self, text):
        m = ASM_RE.match(text)
        addr_str, insn_str = m.groups()
        self.addr = int(addr_str, 16)
        self.insn_str = insn_str

    def __repr__(self):
        return "InAsm(" + hex(self.addr) + ", " + self.insn_str + ")"

    __str__ = __repr__


IMM_RE = re.compile(r"\$0x([0-9a-f]+)")


class Op:
    def __init__(self, text, comment):
        if comment is None:
            self.comment = None
        else:
            self.comment = comment.strip()
        text = text.strip()
        self.opcode, args = text.split()
        self.args = args.split(",")
        self.imms = set()
        for m in IMM_RE.finditer(text):
            (imm_str,) = m.groups()
            self.imms.add(int(imm_str, 16))

    def __repr__(self):
        s = self.opcode + " " + ",".join(self.args)
        if self.comment is not None:
            s += "  # " + self.comment
        return s

    __str__ = __repr__


class OutAsm:
    def __init__(self, text):
        m = ASM_RE.match(text)
        assert m is not None, repr(text)
        addr_str, insn_str = m.groups()
        self.addr = int(addr_str, 16)
        self.insn_str = insn_str

    def __repr__(self):
        return "OutAsm(" + hex(self.addr) + ", " + self.insn_str + ")"

    __str__ = __repr__


class Tb:
    def __init__(self):
        self.in_asm = []
        self.ops = []
        self.out_asm = []
        self.imms = set()
        self.function = None
        self.tbts = []

    def __repr__(self):
        return (
            "Tb("
            + str(self.in_asm)
            + ", "
            + str(self.ops)
            + ", "
            + str(self.out_asm)
            + ")"
        )

    __str__ = __repr__

    @property
    def addr(self):
        return self.in_asm[0].addr

    @property
    def end_addr(self):
        return self.in_asm[-1].addr

    def contains(self, addr):
        return self.addr <= addr < self.end_addr

    def finalize(self):
        for op in self.ops:
            self.imms.update(op.imms)


class TbInTrace:
    def __init__(self, tb, prev, regs):
        self.tb = tb
        self.tb.tbts.append(self)
        self.prev_tbt = prev
        self.next_tbt = None
        if self.prev_tbt is not None:
            self.prev_tbt.next_tbt = self
        self.is_jump = False
        self.is_indirect_jump = False
        self.is_call = False
        self.ret_call_site_tbt = None
        self.writes_to_stdout = False
        self.regs = regs

    def __repr__(self):
        s = hex(self.tb.addr)
        if self.is_indirect_jump:
            s += " [indirect]"
        return s

    __str__ = __repr__


class Function:
    def __init__(self, entry_tb):
        self.tbs = [entry_tb]
        self.callees = set()
        self.callers = defaultdict(list)

    @property
    def addr(self):
        return self.tbs[0].addr

    @property
    def size(self):
        return self.tbs[-1].end_addr - self.addr

    def __hash__(self):
        return hash(self.addr)

    def __eq__(self, other):
        return other is not None and self.addr == other.addr

    def __repr__(self):
        return "sub_" + hex(self.addr)[2:]

    __str__ = __repr__

    def append_tb(self, tb):
        self.tbs.append(tb)
        tb.function = self


PC_RES = [
    (re.compile(r"NIP ([0-9a-f]+)"), None),
    (re.compile(r"RIP=([0-9a-f]+)"), None),
    (re.compile(r"PC = ([0-9a-f]+)"), None),
    (re.compile(r"pc: ([0-9a-f]+)"), None),
    (re.compile(r"IA_F ([0-9a-f]+)"), lambda pc: pc & ~3),
]


def get_pc(line):
    for r, f in PC_RES:
        m = r.search(line)
        if m is not None:
            (pc_str,) = m.groups()
            pc = int(pc_str, 16)
            if f is not None:
                pc = f(pc)
            return pc
    return None


UNIQ_COUNTER = 0


class Region:
    def __init__(self, id):
        self.id = id
        self.bytes = {}

    def load(self, offset, size, little_endian):
        result = []
        for i in range(size):
            result.append(self.load_byte(simplify(offset + size - 1 - i).as_long()))
        if len(result) == 1:
            return result[0]
        if not little_endian:
            result.reverse()
        return simplify(z3.Concat(*result))

    def store(self, offset, value, little_endian):
        size = value.size() // 8
        for i in range(size):
            if little_endian:
                byte_offset = simplify(offset + i).as_long()
            else:
                byte_offset = simplify(offset + size - 1 - i).as_long()
            byte_value = simplify(z3.Extract((i + 1) * 8 - 1, i * 8, value))
            self.bytes[byte_offset] = byte_value

    def load_byte(self, offset):
        value = self.bytes.get(offset)
        if value is None:
            global UNIQ_COUNTER
            value = z3.BitVec(self.id + "_" + str(UNIQ_COUNTER), 8)
            self.bytes[offset] = value
            UNIQ_COUNTER += 1
        return value

    def __repr__(self):
        s = "{"
        for offset in sorted(self.bytes.keys()):
            if s != "{":
                s += ", "
            s += hex(offset) + ": " + str(self.bytes[offset])
        s += "}"
        return s

    __str__ = __repr__

    def clone(self):
        result = Region(self.id)
        result.bytes.update(self.bytes)
        return result


def tcg_parse_bvv(x, n):
    assert x.startswith("$0x"), x
    return z3.BitVecVal(int(x[3:], 16), n)


def tcg_cond(x, cond, y):
    if cond == "lt":
        return x < y
    if cond == "ne":
        return x != y
    if cond == "eq":
        return x == y
    if cond == "ge":
        return x >= y
    if cond == "ltu":
        return z3.ULT(x, y)
    raise Exception(cond)


STATE_ID = 0


def simplify(x):
    return z3.simplify(x)


class State:
    def __init__(self, machine, elfclass, little_endian, tbt):
        self.machine = machine
        self.elfclass = elfclass
        self.little_endian = little_endian
        self.tbt = tbt

    def init(self):
        self.env = z3.BitVec("env", self.elfclass)
        self.tmp = {
            "env": self.env,
        }
        self.region_abs = Region("abs")
        self.region_env = Region("env")
        if self.machine == "EM_X86_64":
            self.region_env.store(
                z3.BitVecVal(0xFFFFFFFFFFFFFFF0, self.elfclass),
                z3.BitVecVal(1, 32),
                self.little_endian,
            )
        elif self.machine == "EM_68K":
            self.region_env.store(
                z3.BitVecVal(0xFFFFFFFFFFFFFFF8, self.elfclass),
                z3.BitVecVal(1, 32),
                self.little_endian,
            )
        elif self.machine == "EM_SPARCV9":
            self.region_env.store(
                z3.BitVecVal(0xfffffffffffffff8, self.elfclass),
                z3.BitVecVal(1, 32),
                self.little_endian,
            )
        elif self.machine == "EM_PARISC":
            self.region_env.store(
                z3.BitVecVal(0xfffffffffffffff8, self.elfclass),
                z3.BitVecVal(1, 32),
                self.little_endian,
            )
        else:
            raise Exception(self.machine)
        self.tmp.update(self.tbt.regs)
        # self.region_abs.store(z3.BitVecVal(0x40007ffb70, 64), z3.BitVecVal(17625276370917932661, 64))  # for checking concrete values
        # assert self.region_abs.load(z3.BitVecVal(0x40007ffb74, 64), 1).as_long() == 0x7a
        self.skip_until_label = None
        self.op_idx = 0
        self.path_condition = []
        self.id = 0
        print("--- " + hex(self.tbt.tb.addr))
        return self

    def clone(self):
        result = State(self.machine, self.elfclass, self.little_endian, self.tbt)
        result.env = self.env
        result.tmp = dict(self.tmp)
        result.region_abs = self.region_abs.clone()
        result.region_env = self.region_env.clone()
        result.skip_until_label = self.skip_until_label
        result.op_idx = self.op_idx
        result.path_condition = list(self.path_condition)
        global STATE_ID
        result.id = STATE_ID
        STATE_ID += 1
        return result

    def get_tmp(self, x, n):
        if x.startswith("$0x"):
            return tcg_parse_bvv(x, n)
        value = self.tmp.get(x)
        if value is None:
            value = z3.BitVec(x + "_0", n)
            self.tmp[x] = value
        return value

    def get_address(self, base, offset):
        address = simplify(
            self.get_tmp(base, self.elfclass) + tcg_parse_bvv(offset, self.elfclass)
        )
        if z3.is_bv_value(address):
            return self.region_abs, address
        return self.region_env, address - self.env

    def goto_next_op(self):
        self.op_idx += 1

    def get_pc(self):
        if self.machine == "EM_68K":
            return self.tmp["PC"]
        elif self.machine == "EM_X86_64":
            return self.region_env.load(
                z3.BitVecVal(0x80, self.elfclass), 8, little_endian=True
            )
        elif self.machine == "EM_SPARCV9":
            return self.tmp["pc"]
        elif self.machine == "EM_PARISC":
            return simplify(self.tmp["iaoq_f"] & ~z3.BitVecVal(3, self.elfclass))
        else:
            raise Exception(self.machine)

    def goto_next_tb(self):
        self.tbt = self.tbt.next_tbt
        self.op_idx = 0
        print("--- " + hex(self.tbt.tb.addr))
        pc = self.get_pc()
        kill = False
        if pc.as_long() != self.tbt.tb.addr:
            print(
                "--- killed: "
                + hex(pc.as_long())
                + "(state) != "
                + hex(self.tbt.tb.addr)
                + "(trace)"
            )
            kill = True
        for reg_name, exp_val in self.tbt.regs.items():
            state_val = self.tmp.get(reg_name)
            if state_val is None:
                continue
            print("--- check " + reg_name + " " + str(state_val) + " " + str(exp_val))
            path_condition = simplify(
                z3.And(*self.path_condition, state_val == exp_val)
            )
            if z3.is_false(path_condition):
                print(
                    "--- killed: "
                    + reg_name
                    + " "
                    + str(state_val)
                    + "(state) vs "
                    + str(exp_val)
                    + "(trace)"
                )
                kill = True
        if kill:
            return []
        return [self]

    def step(self):
        op = self.tbt.tb.ops[self.op_idx]
        print(str(self.op_idx) + ": " + str(op))
        # print(self.tmp)
        if self.skip_until_label is not None:
            if op.opcode == "set_label" and op.args == [self.skip_until_label]:
                self.skip_until_label = None
        elif op.opcode == "ld_i32":
            t0, t1, offset = op.args
            region, address = self.get_address(t1, offset)
            self.tmp[t0] = region.load(address, 4, self.little_endian)
        elif op.opcode == "st_i64":
            t0, t1, offset = op.args
            region, address = self.get_address(t1, offset)
            region.store(address, self.tmp[t0], self.little_endian)
        elif op.opcode == "qemu_ld_i32" or op.opcode == "qemu_ld_i64":
            bits = int(op.opcode[-2:])
            t0, t1, flags, memidx = op.args
            flags = flags.replace("al+", "")  # MO_ALIGN
            flags = flags.replace("un+", "")  # MO_UNALN
            # assert memidx == "0"
            region, address = self.get_address(t1, "$0x0")
            if flags == "ub":
                self.tmp[t0] = z3.ZeroExt(
                    bits - 8, region.load(address, 1, self.little_endian)
                )
            elif flags == "leq":
                self.tmp[t0] = region.load(address, 8, little_endian=True)
            elif flags == "beul":
                self.tmp[t0] = z3.ZeroExt(bits - 32, region.load(address, 4, little_endian=False))
            else:
                raise Exception(op)
        elif op.opcode == "qemu_st_i32" or op.opcode == "qemu_st_i64":
            bits = int(op.opcode[-2:])
            t0, t1, flags, memidx = op.args
            flags = flags.replace("al+", "")  # MO_ALIGN
            flags = flags.replace("un+", "")  # MO_UNALN
            # assert memidx == "0"
            region, address = self.get_address(t1, "$0x0")
            if flags == "leq":
                region.store(address, z3.ZeroExt(64 - bits, self.tmp[t0]), little_endian=True)
            elif flags == "beul":
                region.store(address, z3.ZeroExt(32 - bits, self.tmp[t0]), little_endian=False)
            else:
                raise Exception(op)
        elif op.opcode == "brcond_i32" or op.opcode == "brcond_i64":
            bits = int(op.opcode[-2:])
            t0, t1, cond, label = op.args
            cond_result = simplify(
                tcg_cond(self.get_tmp(t0, bits), cond, self.get_tmp(t1, bits))
            )
            if z3.is_true(cond_result):
                self.skip_until_label = label
            elif z3.is_false(cond_result):
                pass
            else:
                print("--- fork")
                state2 = self.clone()
                state2.path_condition.append(cond_result)
                state2.skip_until_label = label
                state2.goto_next_op()
                self.path_condition.append(z3.Not(cond_result))
                self.goto_next_op()
                return [self, state2]
        elif op.opcode == "mov_i32" or op.opcode == "mov_i64":
            bits = int(op.opcode[-2:])
            t0, t1 = op.args
            self.tmp[t0] = self.get_tmp(t1, bits)
        elif op.opcode == "add_i32" or op.opcode == "add_i64":
            bits = int(op.opcode[-2:])
            t0, t1, t2 = op.args
            self.tmp[t0] = simplify(self.get_tmp(t1, bits) + self.get_tmp(t2, bits))
        elif op.opcode == "sub_i32" or op.opcode == "sub_i64":
            bits = int(op.opcode[-2:])
            t0, t1, t2 = op.args
            self.tmp[t0] = simplify(self.get_tmp(t1, bits) - self.get_tmp(t2, bits))
        elif op.opcode == "and_i32" or op.opcode == "and_i64":
            bits = int(op.opcode[-2:])
            t0, t1, t2 = op.args
            self.tmp[t0] = simplify(self.get_tmp(t1, bits) & self.get_tmp(t2, bits))
        elif op.opcode == "or_i32" or op.opcode == "or_i64":
            bits = int(op.opcode[-2:])
            t0, t1, t2 = op.args
            self.tmp[t0] = simplify(self.get_tmp(t1, bits) | self.get_tmp(t2, bits))
        elif op.opcode == "xor_i32" or op.opcode == "xor_i64":
            bits = int(op.opcode[-2:])
            t0, t1, t2 = op.args
            self.tmp[t0] = simplify(self.get_tmp(t1, bits) ^ self.get_tmp(t2, bits))
        elif op.opcode == "discard":
            (t0,) = op.args
        elif op.opcode == "ext8u_i64":
            t0, t1 = op.args
            self.tmp[t0] = simplify(
                z3.ZeroExt(56, z3.Extract(7, 0, self.get_tmp(t1, 64)))
            )
        elif op.opcode == "ext8s_i64":
            t0, t1 = op.args
            self.tmp[t0] = simplify(
                z3.SignExt(56, z3.Extract(7, 0, self.get_tmp(t1, 64)))
            )
        elif op.opcode == "ext32u_i64":
            t0, t1 = op.args
            self.tmp[t0] = simplify(
                z3.ZeroExt(32, z3.Extract(31, 0, self.get_tmp(t1, 64)))
            )
        elif op.opcode == "ext32s_i64":
            t0, t1 = op.args
            self.tmp[t0] = simplify(
                z3.SignExt(32, z3.Extract(31, 0, self.get_tmp(t1, 64)))
            )
        elif op.opcode == "extu_i32_i64":
            t0, t1 = op.args
            self.tmp[t0] = simplify(z3.ZeroExt(32, self.get_tmp(t1, 32)))
        elif op.opcode == "br":
            (self.skip_until_label,) = op.args
        elif op.opcode == "exit_tb":
            return self.goto_next_tb()
        elif op.opcode == "shl_i32" or op.opcode == "shl_i64":
            bits = int(op.opcode[-2:])
            t0, t1, t2 = op.args
            self.tmp[t0] = simplify(self.get_tmp(t1, bits) << self.get_tmp(t2, bits))
        elif op.opcode == "shr_i32" or op.opcode == "shr_i64":
            bits = int(op.opcode[-2:])
            t0, t1, t2 = op.args
            self.tmp[t0] = simplify(
                z3.LShR(self.get_tmp(t1, bits), self.get_tmp(t2, bits))
            )
        elif op.opcode == "sar_i64":
            t0, t1, t2 = op.args
            self.tmp[t0] = simplify(self.get_tmp(t1, 64) >> self.get_tmp(t2, 64))
        elif op.opcode == "movcond_i64":
            dest, c1, c2, v1, v2, cond = op.args
            self.tmp[dest] = simplify(
                z3.If(
                    tcg_cond(self.get_tmp(c1, 64), cond, self.get_tmp(c2, 64)),
                    self.get_tmp(v1, 64),
                    self.get_tmp(v2, 64),
                )
            )
        elif op.opcode == "call":
            if op.args[0] == "lookup_tb_ptr":  # call lookup_tb_ptr,$0x6,$1,tmp14,env
                self.tmp[op.args[3]] = self.get_tmp("$0x0", 64)
            else:
                raise Exception(op)
        elif op.opcode == "goto_ptr":
            assert self.get_tmp(op.args[0], 64).as_long() == 0
            return self.goto_next_tb()
        elif op.opcode == "set_label":
            (label,) = op.args
        elif op.opcode == "setcond_i32" or op.opcode == "setcond_i64":
            bits = int(op.opcode[-2:])
            dest, t1, t2, cond = op.args
            self.tmp[dest] = z3.simplify(
                z3.If(
                    tcg_cond(self.get_tmp(t1, bits), cond, self.get_tmp(t2, bits)),
                    self.get_tmp("$0x1", bits),
                    self.get_tmp("$0x0", bits),
                )
            )
        elif op.opcode == "deposit_i64":
            dest, t1, t2, pos, len_ = op.args
            pieces = []
            t1 = self.get_tmp(t1, 64)
            t2 = self.get_tmp(t2, 64)
            pos = self.get_tmp(pos, 64).as_long()
            len_ = self.get_tmp(len_, 64).as_long()
            if pos + len_ <= 63:
                pieces.append(z3.Extract(63, pos + len_, t1))
            if len_ >= 1:
                pieces.append(z3.Extract(len_ - 1, 0, t2))
            if pos >= 1:
                pieces.append(z3.Extract(pos - 1, 0, t1))
            if len(pieces) == 1:
                self.tmp[dest] = z3.simplify(pieces[0])
            else:
                self.tmp[dest] = z3.simplify(z3.Concat(*pieces))
        elif op.opcode == "mul_i32" or op.opcode == "mul_i64":
            bits = int(op.opcode[-2:])
            t0, t1, t2 = op.args
            self.tmp[t0] = simplify(self.get_tmp(t1, bits) * self.get_tmp(t2, bits))
        else:
            raise Exception(op)
        self.goto_next_op()
        return [self]


def identify_scanf(main, pc2tb):
    # scanf() is the first function called from main()
    scanf_call_site = None
    for tb in main.tbs:
        for tbt in tb.tbts:
            if tbt.is_call:
                scanf_call_site = tbt
                break
        if scanf_call_site is not None:
            break
    if scanf_call_site is None:
        return None, None
    scanf = scanf_call_site.next_tbt.tb.function
    returns_from_scanf = pc2tb[scanf_call_site.tb.end_addr].tbts
    if len(returns_from_scanf) != 1:
        return None, None
    return scanf, returns_from_scanf[0]


def bb(exe):
    try:
        with open(exe + ".json") as fp:
            existing = json.load(fp)
        existing_value = existing.get("value")
        if existing_value is not None:
            return
    except FileNotFoundError:
        pass
    except JSONDecodeError:
        pass

    with open(exe, "rb") as elf_fp:
        elf = ELFFile(elf_fp)
        machine = elf.header.e_machine
        elfclass = elf.elfclass
        little_endian = elf.little_endian

    trace = exe + ".trace"
    print(trace + ": analyzing")

    line = ""

    def readline():
        nonlocal line
        line = fp.readline()
        return line

    with open(trace) as fp:
        sep = "----------------\n"
        while readline() != sep and line != "":
            pass
        pc2tb = {}
        tbts = []
        prev_tbt = None
        while line == sep:
            tbt = Tb()
            assert readline().startswith("IN:"), repr(line)
            while not readline().startswith("OP:"):
                if line != "\n":
                    tbt.in_asm.append(InAsm(line))

            comment = None
            while not readline().startswith("OUT:"):
                if line.startswith(" ---- "):
                    comment = line
                    continue
                if line != "\n":
                    tbt.ops.append(Op(line, comment))
                    comment = None

            while readline() != "\n":
                if not line.startswith("  --"):
                    tbt.out_asm.append(OutAsm(line))

            # ignore tb recompilations, they seem to be okay
            # assert tbt.addr not in pc2tb, hex(tbt.addr)
            tbt.finalize()
            pc2tb[tbt.addr] = tbt

            regs_so_far = {}
            while line != sep and line != "":
                pc = get_pc(line)
                if pc is not None:
                    tbt = TbInTrace(pc2tb[pc], prev_tbt, regs_so_far)
                    tbts.append(tbt)
                    prev_tbt = tbt
                    regs_so_far = {}
                if "write(1" in line:
                    tbts[-1].writes_to_stdout = True
                m = re.match(
                    "RAX=([0-9a-f]+) RBX=([0-9a-f]+) RCX=([0-9a-f]+) RDX=([0-9a-f]+)",
                    line,
                )
                if m is not None:
                    regs_so_far.update(
                        {
                            "rax": z3.BitVecVal(int(m.group(1), 16), 64),
                            "rbx": z3.BitVecVal(int(m.group(2), 16), 64),
                            "rcx": z3.BitVecVal(int(m.group(3), 16), 64),
                            "rdx": z3.BitVecVal(int(m.group(4), 16), 64),
                        }
                    )
                m = re.match(
                    "RSI=([0-9a-f]+) RDI=([0-9a-f]+) RBP=([0-9a-f]+) RSP=([0-9a-f]+)",
                    line,
                )
                if m is not None:
                    regs_so_far.update(
                        {
                            "rsi": z3.BitVecVal(int(m.group(1), 16), 64),
                            "rdi": z3.BitVecVal(int(m.group(2), 16), 64),
                            "rbp": z3.BitVecVal(int(m.group(3), 16), 64),
                            "rsp": z3.BitVecVal(int(m.group(4), 16), 64),
                        }
                    )
                m = re.match(
                    "R8 =([0-9a-f]+) R9 =([0-9a-f]+) R10=([0-9a-f]+) R11=([0-9a-f]+)",
                    line,
                )
                if m is not None:
                    regs_so_far.update(
                        {
                            "r8": z3.BitVecVal(int(m.group(1), 16), 64),
                            "r9": z3.BitVecVal(int(m.group(2), 16), 64),
                            "r10": z3.BitVecVal(int(m.group(3), 16), 64),
                            "r11": z3.BitVecVal(int(m.group(4), 16), 64),
                        }
                    )
                m = re.match(
                    "R12=([0-9a-f]+) R13=([0-9a-f]+) R14=([0-9a-f]+) R15=([0-9a-f]+)",
                    line,
                )
                if m is not None:
                    regs_so_far.update(
                        {
                            "r12": z3.BitVecVal(int(m.group(1), 16), 64),
                            "r13": z3.BitVecVal(int(m.group(2), 16), 64),
                            "r14": z3.BitVecVal(int(m.group(3), 16), 64),
                            "r15": z3.BitVecVal(int(m.group(4), 16), 64),
                        }
                    )
                m = re.match(r"D6 = ([0-9a-f]+)   A6 = ([0-9a-f]+)", line)
                if m is not None:
                    # xxx update tbts[-1] since pc comes earlier?
                    regs_so_far.update(
                        {
                            "D6": z3.BitVecVal(int(m.group(1), 16), 32),
                            "A6": z3.BitVecVal(int(m.group(2), 16), 32),
                        }
                    )
                m = re.match(r"%i4-7: ([0-9a-f]+) ([0-9a-f]+) ([0-9a-f]+) ([0-9a-f]+)", line)
                if m is not None:
                    tbts[-1].regs.update({
                        "i4": z3.BitVecVal(int(m.group(1), 16), 64),
                        "i5": z3.BitVecVal(int(m.group(2), 16), 64),
                        "i6": z3.BitVecVal(int(m.group(3), 16), 64),
                        "i7": z3.BitVecVal(int(m.group(4), 16), 64),
                    })
                m = re.match(r"GR04 ([0-9a-f]+) GR05 ([0-9a-f]+) GR06 ([0-9a-f]+) GR07 ([0-9a-f]+)", line)
                if m is not None:
                    tbts[-1].regs.update({
                        "r4": z3.BitVecVal(int(m.group(1), 16), 32),
                        "r5": z3.BitVecVal(int(m.group(2), 16), 32),
                        "r6": z3.BitVecVal(int(m.group(3), 16), 32),
                        "r7": z3.BitVecVal(int(m.group(4), 16), 32),
                    })
                m = re.match(r"GR24 ([0-9a-f]+) GR25 ([0-9a-f]+) GR26 ([0-9a-f]+) GR27 ([0-9a-f]+)", line)
                if m is not None:
                    tbts[-1].regs.update({
                        "r24": z3.BitVecVal(int(m.group(1), 16), 32),
                        "r25": z3.BitVecVal(int(m.group(2), 16), 32),
                        "r26": z3.BitVecVal(int(m.group(3), 16), 32),
                        "r27": z3.BitVecVal(int(m.group(4), 16), 32),
                    })
                readline()

        assert line == "", repr(line)

        # jump analysis
        tbt_iter = iter(tbts)
        prev_tbt = next(tbt_iter)
        jump_tbts = []
        prev_tbt.tb.function = Function(prev_tbt.tb)
        pc2function = {prev_tbt.tb.addr: prev_tbt.tb.function}
        for tbt in tbt_iter:
            if tbt.tb.addr != prev_tbt.tb.end_addr:
                prev_tbt.is_jump = True
                imms = prev_tbt.tb.imms
                if machine == "EM_PARISC":
                    imms = [imm & ~3 for imm in imms]
                if tbt.tb.addr not in imms:
                    prev_tbt.is_indirect_jump = True
                    for jump_tbt in reversed(jump_tbts):
                        # We are jumping right after a jump we've made before.
                        # This must be a return, and they original just must be
                        # a call. Exception: if we already know the original
                        # jump is a return, it must be that the next function
                        # is located right next after this return.
                        if (
                            tbt.tb.addr == jump_tbt.tb.end_addr
                            and jump_tbt.ret_call_site_tbt is None
                        ):
                            prev_tbt.ret_call_site_tbt = jump_tbt
                            jump_tbt.is_call = True
                            if jump_tbt.tb.addr not in pc2function:
                                entry_tb = jump_tbt.next_tbt.tb
                                entry_tb.function = Function(entry_tb)
                                pc2function[entry_tb.addr] = entry_tb.function
                            break
                jump_tbts.append(prev_tbt)
            prev_tbt = tbt

        # identify functions (1): take TBs adjacent to entry points
        for pc in sorted(pc2function.keys(), reverse=True):
            function = pc2function[pc]
            while True:
                tb = pc2tb.get(function.tbs[-1].end_addr)
                if tb is None or tb.function is not None:
                    break
                function.append_tb(tb)

        # identify functions (2): assign orphan TBs to nearby functions
        last_function = None
        for pc in sorted(pc2tb.keys()):
            tb = pc2tb[pc]
            if tb.function is None:
                last_function.append_tb(tb)
            else:
                last_function = tb.function

        # create call graph
        for function in pc2function.values():
            for tb in function.tbs:
                for tbt in tb.tbts:
                    if tbt.is_call:
                        function.callees.add(tbt.next_tbt.tb.function)
                        tbt.next_tbt.tb.function.callers[function].append(tbt)

        # identify sys_write
        sys_write = None
        for function in pc2function.values():
            for tb in function.tbs:
                for tbt in tb.tbts:
                    if tbt.writes_to_stdout:
                        if sys_write is None:
                            sys_write = tbt.tb.function
                            if machine == "EM_PARISC" and sys_write.addr == 0x100:
                                # syscall
                                sys_write = tbt.prev_tbt.tb.function
                        elif sys_write != tbt.tb.function:
                            raise Exception("Multiple sys_write candidates")
        if sys_write is None:
            raise Exception("No sys_write")

        # identify main and puts - walk up the call graph from sys_write and
        # take the topmost indirectly called function
        main = None
        puts = None
        scanf = None
        return_from_scanf = None
        queue = [(sys_write, None)]
        seen = set()
        while len(queue) > 0:
            print(queue)
            current, prev = queue.pop()
            for caller, call_site_tbts in current.callers.items():
                for call_site_tbt in call_site_tbts:
                    if call_site_tbt.is_indirect_jump and 2 <= len(current.callees):
                        maybe_scanf, maybe_return_from_scanf = identify_scanf(
                            current, pc2tb
                        )
                        if (
                            maybe_scanf is not None
                            and maybe_scanf != current
                            and maybe_scanf != prev
                            and maybe_return_from_scanf is not None
                            and len(prev.callers) == 1  # puts has just 1 caller
                        ):
                            main = current
                            puts = prev
                            scanf = maybe_scanf
                            return_from_scanf = maybe_return_from_scanf
                if caller not in seen:
                    queue.append((caller, current))
                    seen.add(caller)
        #if main is None or puts is None:
        #    raise Exception("No main/puts/scanf")

        # pretty print trace
        indent = 0
        for tbt in tbts:
            s = ("    " * indent) + hex(tbt.tb.addr)
            if tbt.is_jump:
                s += " [jump]"
            if tbt.is_call:
                indent += 1
                if tbt.is_indirect_jump:
                    s += " [indirect call]"
                else:
                    s += " [call]"
            if tbt.ret_call_site_tbt is not None:
                indent -= 1
                s += " [ret, called by " + hex(tbt.ret_call_site_tbt.tb.addr) + "]"
            if tbt.tb.function is not None:
                s += " [" + str(tbt.tb.function) + "]"
            print(s)
            # if indent < 0:
            #    raise Exception("call/ret mismatch")
        # if indent != 0:
        #    raise Exception("call/ret mismatch")

        # pretty print functions
        for pc in sorted(pc2function.keys()):
            function = pc2function[pc]
            print(
                "sub: "
                + hex(pc)[2:]
                + "-"
                + hex(function.tbs[-1].end_addr)[2:]
                + " ("
                + str(function.tbs[-1].end_addr - pc)
                + " bytes, "
                + str(len(function.callers))
                + " callers, "
                + str(len(function.callees))
                + " callees)"
            )
            if function == sys_write:
                print("    [sys_write]")
            if function == main:
                print("    [main]")
            if function == scanf:
                print("    [scanf]")
            if function == puts:
                print("    [puts]")
            for callee in function.callees:
                print("    callee: " + str(callee))
            for caller, call_sites in function.callers.items():
                print("    caller: " + str(caller))
                for call_site in call_sites:
                    print("        call site: " + str(call_site))

        # symbolic execution after scanf
        states = [State(machine, elfclass, little_endian, return_from_scanf).init()]
        while len(states) > 0:
            state = states.pop()
            if state.tbt.is_call and state.tbt.next_tbt.tb.function == puts:
                print("--- puts reached with " + str(state.path_condition))
                value = []
                prev_addr = 0
                for addr in sorted(state.region_abs.bytes.keys()):
                    if addr != prev_addr + 1:
                        value.clear()
                    byte_value = state.region_abs.bytes[addr]
                    if z3.is_app_of(byte_value, z3.Z3_OP_UNINTERPRETED):
                        value.append(byte_value)
                    if len(value) == 8:
                        break
                    prev_addr = addr
                else:
                    raise Exception("Cannot reconstruct the input value")
                print("value@" + hex(addr - 7))
                if not little_endian:
                    value.reverse()
                solver = z3.Solver()
                # flip random branches
                for path_condition_item in state.path_condition:
                    if random.randint(0, 1) == 0:
                        solver.add(path_condition_item)
                    else:
                        solver.add(z3.Not(path_condition_item))
                if str(solver.check()) != "sat":
                    print("--- unsat")
                    continue
                solution = 0
                for i, x in enumerate(value):
                    x = solver.model()[x]
                    if x is not None:
                        solution += x.as_long() << (i * 8)
                print(solution)
                with open(exe + ".json", "w") as hint_fp:
                    json.dump(
                        {
                            "exe": exe,
                            "value-hint": solution,
                        },
                        hint_fp,
                    )
                return
            states.extend(state.step())


def main():
    (exe,) = sys.argv[1:]
    exes = [
        exe
        for exe in glob(exe)
        if os.access(exe, os.X_OK) and os.path.exists(exe + ".trace")
    ]
    random.shuffle(exes)
    for exe in exes:
        bb(exe)


if __name__ == "__main__":
    main()
