---
layout: post
redirect_from:
  - /blog/2016/09/05/twctf-2016-rps-ng/
date: "2016-09-05T13:15:47+09:00"
tags: [ "ctf", "writeup", "ppc", "mmactf", "twctf" ]
"target_url": [ "https://score.ctf.westerns.tokyo/problems/33" ]
---

# Tokyo Westerns/MMA CTF 2nd 2016: rps-ng

2015年のrpsは解けなかったがこれはまあ取れた。

## solution

The program tries to predict our hands with simple algorithm.
We can predict the prediction.

The initial value of `table` is unknown, our prediction cannot be complete one.
But, we can try many times, and sometimes win $40$ times. So it's ok.

## implementation

``` python
#!/usr/bin/env python2
import copy
from pwn import * # https://pypi.python.org/pypi/pwntools
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('host', nargs='?', default='ppc1.chal.ctf.westerns.tokyo')
parser.add_argument('port', nargs='?', default=15376, type=int)
args = parser.parse_args()

def init_table():
    return [ [ random.randint(0, 2) for j in range(3) ] for i in range(3) ], 0
def update_table(table, last, c):
    table = copy.deepcopy(table)
    table[last][c] += 1
    return table, c
def next_hand(table, last):
    m = max(table[last])
    ret = table[last].index(m)
    return (ret + 1) % 3

p = remote(args.host, args.port)
table, last = init_table()
for _ in range(50):
    p.recvuntil('Rock? Paper? Scissors? [RPS]')
    c = (next_hand(table, last) + 1) % 3
    p.sendline('RPS'[c])
    p.recvline()
    result = p.recvline().strip()
    if result == 'You lose':
        table[last][c] = max(table[last])
        if next_hand(table, last) != c:
            table[last][c] += 1
    elif result == 'Draw':
        table[last][(c-1)%3] = max(table[last])
        if next_hand(table, last) != (c-1)%3:
            table[last][(c-1)%3] += 1
    elif result == 'You win!!':
        pass
    table, last = update_table(table, last, c)
    log.info(p.recvline())
log.info(p.recvall()) # TWCTF{The_hand_is_determined_by_mien}
```
