#!/usr/bin/env python3
import json

from networkx import DiGraph
from networkx.algorithms import shortest_path

p = json.load(open('data.json'))
p = p[1][1]
start_id = p[0][0]
g = DiGraph()
for x in p:
    g.add_node(x[0])
for i, x in enumerate(p):
    if x[3] == 8:
        g.add_edge(x[0], p[i + 1][0])
    if len(x) > 4 and x[4] is not None and x[4][0][1] is not None:
        for y in x[4][0][1]:
            g.add_edge(x[0], y[2], label=y[0])
q = shortest_path(g, 938169490, 751651474)
ll = ''
for i in range(len(q) - 1):
    d = g.get_edge_data(q[i], q[i + 1])
    l = d.get('label')
    if l:
        ll += l
ll = f'pbctf{{{ll}_s3cuR3_p1n_id_2_3v3ry0ne}}'
print(ll)
