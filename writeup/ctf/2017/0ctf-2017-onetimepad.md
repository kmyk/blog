---
layout: post
alias: "/blog/2017/03/22/0ctf-2017-onetimepad/"
date: "2017-03-22T16:51:53+09:00"
title: "0ctf 2017: oneTimePad"
tags: [ "ctf", "writeup", "0ctf", "crypto" ]
---

## solution

線形性に気付いて復元。

`generator.next()` の$2,3$回目の出力は分かるので、$1$回目の出力を求めればよい。
`seed`, `key`と$2$変数あるので、`process(m, k)`の逆関数を書くことになる。

ここで`process`は以下のような性質を持つ。

-   `process(tmp=m ^ k)` という$1$変数関数と見做してよい
-   線形性: `process(x) ^ process(y) == process(x ^ y)`

この線形性により、`process`の逆関数`x = invert(y)`はその`y`を$0$にするように掃き出し法やLights Out風の探索で実装できる。

## implementation

``` python
#!/usr/bin/env python2
from os import urandom
def str2num(s):
    return int(s.encode('hex'), 16)
def num2str(n):
    return hex(n)[2:].rstrip('L').decode('hex')

ctxt1 = 0xaf3fcc28377e7e983355096fd4f635856df82bbab61d2c50892d9ee5d913a07f
ctxt2 = 0x630eb4dce274d29a16f86940f2f35253477665949170ed9e8c9e828794b5543c
ctxt3 = 0xe913db07cbe4f433c7cdeaac549757d23651ebdccf69d7fbdfd5dc2829334d1b
fake_secret1 = 'I_am_not_a_secret_so_you_know_me'
fake_secret2 = 'feeddeadbeefcafefeeddeadbeefcafe'
generator2 = ctxt2 ^ str2num(fake_secret1)
generator3 = ctxt3 ^ str2num(fake_secret2)
assert generator2 == 0x2a51d5b1bd1abdee4999363397902036332916fbce0982ebd3f5ece8e3ea3959
assert generator3 == 0x8f76be63af819557a5a88fca37f631b750348eb8ab0cb69fbdb0b94e4a522b7e

P = (1 << 256) + 0x425
def process(x):
    assert (1 << 256) > x
    y = 0
    for i in bin(x)[2:]:
        y <<= 1
        if int(i):
            y ^= x
        if y >> 256:
            y ^= P
    return y

import random
for _ in range(1000):
    x = random.randrange(1 << 256)
    y = random.randrange(1 << 256)
    assert process(x) ^ process(y) == process(x ^ y)

def ilog2(n):
    if n == 0:
        return -1
    return len(bin(n)) - 3
table = [ list() for _ in range(256) ]
for i in range(256):
    proc_i = process(1 << i)
    table[ilog2(proc_i)] += [( 1 << i, proc_i )]
for i in reversed(list(range(256))):
    table[i] = sorted(list(set(table[i])))
    for j, proc_j in table[i]:
        for k, proc_k in table[i]:
            jk = j ^ k
            proc_jk = proc_j ^ proc_k
            if proc_jk == 0:
                continue
            table[ilog2(proc_jk)] += [( jk, proc_jk )]
def recur(y, i):
    if i == -1:
        if y == 0:
            return 0
        else:
            return
    else:
        if y & (1 << i):
            for j, proc_j in table[i]:
                x = recur(y ^ proc_j, i-1)
                if x is not None:
                    return x ^ j
        else:
            return recur(y, i-1)
def unprocess(y):
    return recur(y, 255)

seed = unprocess(generator3) ^ generator2
generator1 = unprocess(generator2) ^ seed
true_secret = generator1 ^ ctxt1
print(repr('flag{' + num2str(true_secret) + '}'))
```
