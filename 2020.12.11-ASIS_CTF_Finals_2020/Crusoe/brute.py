#!/usr/bin/env python3
import string
import subprocess

W = 9
H = 5
ALPHABET = (string.ascii_letters + string.digits + '{}').encode()


def enc2sym(enc, x, y):
    sym = []
    start = y * H
    end = (y + 1) * H - 1
    if end >= len(enc):
        return None
    assert enc[end] == ''
    for yy in range(start, end):
        sym.append(tuple(enc[yy][x * W:(x + 1) * W]))
    return tuple(sym)


def print_syms(sym):
    print('!' * (W + 2))
    for row in sym:
        print('!' + ''.join(row) + '!')
    print('!' * (W + 2))


def enc2syms(enc):
    raw_chars = enc.split('\n')
    result = []
    for y in range(8):
        for x in range(8):
            sym = enc2sym(raw_chars, x, y)
            if sym is None:
                break
            result.append(sym)
    return result


def plain2syms(plain):
    enc = subprocess.check_output(['./crusoe'], input=plain).decode()
    return enc2syms(enc)


def get_common_prefix(x, y):
    prefix = []
    for i in range(min(len(x), len(y))):
        if x[i] == y[i]:
            prefix.append(x[i])
        else:
            break
    return prefix


def search(plain_flag, exp_syms):
    flag_syms = plain2syms(plain_flag)
    if flag_syms == exp_syms:
        print(plain_flag)
        return
    prefix0 = get_common_prefix(flag_syms, exp_syms)
    for c in ALPHABET:
        plain_flag1 = plain_flag + bytes((c,))
        flag_syms1 = plain2syms(plain_flag1)
        prefix1 = get_common_prefix(flag_syms1, exp_syms)
        if len(prefix1) > len(prefix0):
            search(plain_flag1, exp_syms)


def main():
    with open('flag.crusoe') as fp:
        exp_enc = fp.read()
    exp_syms = enc2syms(exp_enc)
    search(b'', exp_syms)
    # cvnjubctjunvtmdnfmtbwmbkbgfmgjgdtvjnfczzfbgfyzbdtbbbebknzufgvsK
    # nc 66.172.10.203 9999
    # ASIS{cRuS03_10V3__0bFu5c4T3d__c0COnu75!!}


if __name__ == '__main__':
    main()
