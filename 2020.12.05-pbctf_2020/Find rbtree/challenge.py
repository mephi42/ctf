#!/usr/bin/env python3
import random
import itertools


welcome = r"""
  _____              _   _    ____          ____       ____    _____    ____    U _____ uU _____ u 
 |" ___|    ___     | \ |"|  |  _"\      U |  _"\ u U | __")u |_ " _|U |  _"\ u \| ___"|/\| ___"|/ 
U| |_  u   |_"_|   <|  \| |>/| | | |      \| |_) |/  \|  _ \/   | |   \| |_) |/  |  _|"   |  _|"   
\|  _|/     | |    U| |\  |uU| |_| |\      |  _ <     | |_) |  /| |\   |  _ <    | |___   | |___   
 |_|      U/| |\u   |_| \_|  |____/ u      |_| \_\    |____/  u |_|U   |_| \_\   |_____|  |_____|  
 )(\\,-.-,_|___|_,-.||   \\,-.|||_         //   \\_  _|| \\_  _// \\_  //   \\_  <<   >>  <<   >>  
(__)(_/ \_)-' '-(_/ (_")  (_/(__)_)       (__)  (__)(__) (__)(__) (__)(__)  (__)(__) (__)(__) (__)
"""

prop = {
    "Eyewear": ["Glasses", "Monocle", "None"],
    "Eye color": ["Brown", "Blue", "Hazel"],
    "Hair": ["Straight", "Curly", "Bald"],
    "Outerwear": ["Coat", "Hoodie", "Poncho"],
    "T-shirt color": ["Red", "Orange", "Green"],
    "Trousers": ["Jeans", "Leggings", "Sweatpants"],
    "Socks color": ["Black", "Gray", "White"],
    "Shoes": ["Boots", "Slippers", "Sneakers"],
}


def stage(num_stage, num_people, num_ask):
    print("STAGE {} / 30".format(num_stage))
    print("Generating people... (and rbtree)")

    people = list(itertools.product(*prop.values()))
    random.shuffle(people)
    people = people[:num_people]
    rbtree = random.choice(people)

    print("=" * 29)
    for idx, person in enumerate(people):
        print(" ".join(" [PERSON {:4d}] ".format(idx + 1)))
        for prop_name, prop_val in zip(prop.keys(), person):
            print("{:14s}: {}".format(prop_name, prop_val))
        print("=" * 29)

    print("Now ask me!")

    for i in range(num_ask):
        prop_name = input("? > ")
        if prop_name == 'Solution':
            break
        if prop_name not in prop:
            return False
        
        prop_ask = input("! > ").strip().split(' ')
        for val in prop_ask:
            if val not in prop[prop_name]:
                return False

        if set(rbtree) & set(prop_ask):
            print("YES")
        else:
            print("NO")

    rbtree_guess = tuple(input("rbtree > ").strip().split(' '))

    if rbtree == rbtree_guess:
        return True
    else:
        return False


def main():
    print(welcome)

    cases = [(5, 3), (7, 3), (10, 4), (15, 4), (20, 5), (25, 5), (50, 6), (75, 7), (100, 8), (250, 9)]
    cases += [(400, 10)] * 5 + [(750, 11)] * 5 + [(1000, 12)] * 5 + [(1600, 12)] * 5

    for idx, (num_people, num_ask) in enumerate(cases):
        if not stage(idx + 1, num_people, num_ask):
            print("WRONG :(")
            return
        print("You found rbtree!")

    with open("flag.txt", "r") as f:
        print(f.read())


if __name__ == "__main__":
    try:
        main()
    finally:
        print("BYEBYE!")
        exit(0)