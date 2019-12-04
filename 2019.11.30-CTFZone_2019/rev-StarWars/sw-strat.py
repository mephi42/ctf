#!/usr/bin/env pypy3
import json


def fight(attacker, defender):
    attacker_shield = attacker['shield']
    defender_shield = defender['shield']
    if attacker_shield < 0:
        return False
    while True:
        defender_shield -= attacker['attack']
        if defender_shield < 0:
            return True
        attacker_shield -= defender['attack']
        if attacker_shield < 0:
            return False


def popcnt(x):
    n = 0
    while x > 0:
        n += (x & 1)
        x >>= 1
    return n


def best_moves(shield, attack, history, progression, kills, npcs):
    if len(history) >= len(progression):
        return None

    potential_moves = []
    human = {'shield': shield, 'attack': attack}
    if fight(human, npcs[0]):
        potential_moves.append(dict(
            shield=max(shield, npcs[0]['shield']),
            attack=(attack + npcs[0]['attack']) % 0x100,
            history=history + [(shield, attack, 0)],
            progression=progression,
            kills=kills,
            npcs=npcs[1:],
        ))
    for ai_index, (ai_shield, ai_attack) in enumerate(progression[len(history)]):
        if ai_index == 0:
            continue
        if kills & (1 << ai_index):
            continue
        if ai_shield == 10000:
            print(history)
            print('FAIL: ' + str(ai_index) + ' became too strong (have ' + str((shield, attack)) + ')')
            return None
        if fight(human, {'shield': ai_shield, 'attack': ai_attack}):
            next_shield = max(shield, ai_shield)
            next_attack = (attack + ai_attack) % 0x100
            next_history = history + [(shield, attack, ai_index)]
            next_kills = kills | (1 << ai_index)
            if next_kills == 0b11111111111111110:
                return next_history
            if fight({'shield': next_shield, 'attack': next_attack}, npcs[0]):
                next_shield = max(next_shield, npcs[0]['shield'])
                next_attack = (next_attack + npcs[0]['attack']) % 0x100
                potential_moves.append(dict(
                    shield=next_shield,
                    attack=next_attack,
                    history=next_history,
                    progression=progression,
                    kills=next_kills,
                    npcs=npcs[1:],
                ))

    potential_moves.sort(key=lambda x: 1000 if x['history'][-1] == 0 else -x['shield'] - x['attack'])
    best_history = None
    for potential_move in potential_moves:
        potential_history = best_moves(**potential_move)
        if potential_history is not None and (best_history is None or len(potential_history) < len(best_history)):
            best_history = potential_history

    return best_history


with open('sw.json') as fp:
    stats = json.load(fp)
npc_indices = [0] * 17
progression = [[(p['ship']['shield'], p['ship']['attack']) for p in stats['players']]]
for _ in range(26):
    progression.append([])
    for i, p in enumerate(stats['players']):
        npc = stats['npcs'][p['npcs'][npc_indices[i]]]
        shield, attack = progression[-2][i]
        if i == 0:
            print('You ' + p['ship']['name'] + ' has ' + str(shield) + ' shield and ' + str(attack) + ' attack power')
        if shield is not None and attack is not None:
            print(p['ship']['name'] + ' wandering through the depths of space has discovered the ' + npc['name'])
            print(p['ship']['name'] + ' attacks the ' + npc['name'] + ' for the glory!')
            if fight({'shield': shield, 'attack': attack}, npc):
                print(p['ship']['name'] + ' destroys ' + npc['name'] + ' and takes their weapons and shields')
                progression[-1].append((
                    max(shield, npc['shield']),
                    (attack + npc['attack']) % 0x100,
                ))
                npc_indices[i] += 1
            else:
                progression[-1].append((None, None))
        else:
            progression[-1].append((None, None))
for i, npc in enumerate(stats['npcs']):
    print(str(i) + ': ' + str(npc))
for i, player in enumerate(stats['players']):
    print(str(i) + ': ' + str(player))
for x in progression:
    print(x)
p = stats['players'][0]
print(best_moves(
    shield=p['ship']['shield'],
    attack=p['ship']['attack'],
    history=[],
    progression=progression,
    kills=0,
    npcs=[stats['npcs'][npc_index] for npc_index in p['npcs']],
))
