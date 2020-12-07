#!/usr/bin/env pypy3
from pwn import *

GUESS_PROMPT = b'? > '
SOLUTION_PROMPT = b'rbtree > '
PROPS = (
    (b'Eyewear', (b'Glasses', b'Monocle', b'None')),
    (b'Eye color', (b'Brown', b'Blue', b'Hazel')),
    (b'Hair', (b'Straight', b'Curly', b'Bald')),
    (b'Outerwear', (b'Coat', b'Hoodie', b'Poncho')),
    (b'T-shirt color', (b'Red', b'Orange', b'Green')),
    (b'Trousers', (b'Jeans', b'Leggings', b'Sweatpants')),
    (b'Socks color', (b'Black', b'Gray', b'White')),
    (b'Shoes', (b'Boots', b'Slippers', b'Sneakers')),
)
DEPTHS = {
    5: 3,
    7: 3,
    10: 4,
    15: 4,
    20: 5,
    25: 5,
    50: 6,
    75: 7,
    100: 8,
    250: 9,
    400: 10,
    750: 11,
    1000: 12,
    1600: 12,
}


def connect():
    if args.LOCAL:
        return process(['./challenge.py'])
    else:
        return remote('find-rbtree.chal.perfect.blue', 1)


def parse_stage(tube, num_stage):
    tube.recvuntil('STAGE {} / 30\n'.format(num_stage).encode())
    assert tube.recvline() == b'Generating people... (and rbtree)\n'
    assert tube.recvline() == b'=============================\n'
    person_idx = 0
    matrix = []
    while True:
        person_line = tube.recvline()
        if person_line == b'Now ask me!\n':
            return matrix
        person_line_exp = (' '.join(' [PERSON {:4d}] '.format(person_idx + 1)) + '\n').encode()
        assert person_line_exp == person_line, (person_line_exp, person_line)
        person_idx += 1
        line = [-1] * len(PROPS)
        for prop_idx in range(8):
            prop_name, prop_val = tube.recvline().split(b':')
            prop_name = prop_name.strip()
            prop_val = prop_val.strip()
            prop_name_exp = PROPS[prop_idx][0]
            assert prop_name_exp == prop_name, (prop_name_exp, prop_name)
            line[prop_idx] = PROPS[prop_idx][1].index(prop_val)
        assert tube.recvline() == b'=============================\n'
        matrix.append(line)


def eval_split(matrix, prop_idx):
    counts = [0, 0, 0]
    for person in matrix:
        counts[person[prop_idx]] += 1
    min_prop_val_idx = None
    min_prop_val_delta = None
    for prop_val_idx in range(3):
        prop_val_delta = abs(counts[prop_val_idx] - len(matrix) / 2)
        if min_prop_val_idx is None or prop_val_delta < min_prop_val_delta:
            min_prop_val_idx = prop_val_idx
            min_prop_val_delta = prop_val_delta
    return min_prop_val_idx, min_prop_val_delta


def iter_splits(matrix):
    splits = []
    for prop_idx in range(len(PROPS)):
        prop_val_idx, prop_val_delta = eval_split(matrix, prop_idx)
        splits.append((prop_val_delta, prop_idx, prop_val_idx))
    splits.sort()
    return splits


def do_split(matrix, prop_idx, prop_val_idx):
    matrix1 = []
    matrix2 = []
    for person in matrix:
        if person[prop_idx] == prop_val_idx:
            matrix1.append(person)
        else:
            matrix2.append(person)
    return matrix1, matrix2


MAX_DEPTH_REACHED = 'MAX_DEPTH_REACHED'


def build_tree(matrix, max_depth, desperation, depth):
    if len(matrix) == 0:
        return None
    if len(matrix) == 1:
        return matrix[0],
    if depth == max_depth:
        return MAX_DEPTH_REACHED
    for prop_val_delta, prop_idx, prop_val_idx in iter_splits(matrix):
        matrix1, matrix2 = do_split(matrix, prop_idx, prop_val_idx)
        node1 = build_tree(matrix1, max_depth, desperation, depth + 1)
        if node1 is MAX_DEPTH_REACHED:
            if depth > desperation:
                return MAX_DEPTH_REACHED
            continue
        node2 = build_tree(matrix2, max_depth, desperation, depth + 1)
        if node2 is MAX_DEPTH_REACHED:
            if depth > desperation:
                return MAX_DEPTH_REACHED
            continue
        return prop_idx, prop_val_idx, node1, node2
    return MAX_DEPTH_REACHED


def format_person(person):
    return b' '.join(
        prop[1][prop_val_idx]
        for prop_val_idx, prop in zip(person, PROPS)
    )


def do_stage(tube, num_stage):
    matrix = parse_stage(tube, num_stage)
    print(matrix)
    max_depth = DEPTHS[len(matrix)]
    for desperation in range(max_depth):
        tree = build_tree(matrix, max_depth, desperation, 0)
        print((tree, desperation))
        if tree is not MAX_DEPTH_REACHED:
            break
    else:
        raise Exception('wtf')
    while True:
        assert tree is not None
        prompt = tube.recvuntil((GUESS_PROMPT, SOLUTION_PROMPT))
        if len(tree) == 1:
            if prompt != SOLUTION_PROMPT:
                tube.sendline(b'Solution')
                tube.recvuntil(SOLUTION_PROMPT)
            tube.sendline(format_person(tree[0]))
            break
        assert prompt == GUESS_PROMPT, prompt
        prop_idx, prop_val_idx, node1, node2 = tree
        tube.sendline(PROPS[prop_idx][0])
        tube.recvuntil(b'! > ')
        tube.sendline(PROPS[prop_idx][1][prop_val_idx])
        yes_no = tube.recvline().strip()
        if yes_no == b'YES':
            tree = node1
        else:
            assert yes_no == b'NO'
            tree = node2


def main():
    with connect() as tube:
        for num_stage in range(30):
            do_stage(tube, num_stage + 1)
        tube.interactive()  # pbctf{rbtree_is_not_bald,_and_does_not_wear_poncho}


if __name__ == '__main__':
    main()
