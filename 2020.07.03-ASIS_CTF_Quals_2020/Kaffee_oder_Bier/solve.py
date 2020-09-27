#!/usr/bin/env python3
mapping = {}
with open('dict') as fp:
    for line in fp:
        x, y = line.split()
        mapping[y] = chr(int(x))
flag = [
    '463579968','153665123','71771832','4077432464','2905392055','2639166381','71771832','2726012337','3287406603','2327569054','2814748473','71771832','2997963156','3963652876','463579968','71771832','659572563','1443809702','951873430','1443809702','4883209440','1443809702','272908422','3387877500','1289979018','3287406603','307126039','2186972133','1387136247','307126039','4311457779','805374718','3880356379','349848049','2639166381','2186972133','4431761078','272908422','396361187','909035002','2186972133','1186356121','4193363865','3387877500','2407469004','307126039','3880356379','349848049','78252962','5146902843'
]
print(''.join([mapping[x] for x in flag]))