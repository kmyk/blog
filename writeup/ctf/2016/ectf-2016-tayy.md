---
layout: post
alias: "/blog/2016/10/23/ectf-2016-tayy/"
date: "2016-10-23T23:49:35+09:00"
title: "ECTF 2016: tayy"
tags: [ "ctf", "ectf", "rev", "z3" ]
"target_url": [ "http://www.ectf.in/" ]
---

## problem

<https://twitter.com/tayandyou>

``` sh
$ ./tayy
=============================================================
Welcome to the future of AI, developed by NIA Research, Tayy!
=============================================================
1. Talk to Tayy.
2. Flag?
0. Exit.
> 1
=============================================================
1. Ayy lmao, Tayy lmao.
2. You are very cruel.
3. Memes are lyf.
4. Go away!.
5. zzzz
6. Cats > Dogs.
7. Dogs > Cats.
8. AI is overrated?.
9. I dont like you.
0. <exit to menu>
> 8
Tayy: Die, human!

=============================================================
1. Talk to Tayy.
2. Flag?
0. Exit.
> 2
Flag: EMhd?^\67cTC<y^D=?SLCSL]AVUS#Yo?l-4^_s
=============================================================
1. Talk to Tayy.
2. Flag?
0. Exit.
> 0
```

Tay has a flag string.
It is modified depending on your choice at `1. Talk to Tayy.`, and readable via `2. Flag?`.

## solution

The program is like below.
The original `%` is C's one, so below example sometimes returns wrong results if the argument has negative integer.

``` python
#!/usr/bin/env python2
def tayy(key):
    flag = map(ord, "4545584c831918231c404e35265b03672c713248373f30393a473e34214f5d694a28270a56".decode("hex"))
    for i in range(len(key)):
        for k in range(len(flag)):
            if i % 2 == 0:
                flag[k] += k * key[i] % 37
            else:
                flag[k] -= k * key[i] % 37
            flag[k] %= 256
    return ''.join(map(chr, flag))
print tayy([1, 2, 3])
```

You can get flag using z3. You should not forget that it accepts arbitrary integer, not only $1, 2, \dots, 9, 0$.

`ECTF{41_1S_D3f1n1t3lY_N0T_TH3_FuTUR3}`.

## implementation

This implementation has appearent bug around the `%`. But I got the flag luckily, so it is not fixed.

``` python
#!/usr/bin/env python2
from z3 import *

s = Solver()
flag = [Int('flag_%d' % i) for i in range(37)]
key  = [Int('key_%d'  % i) for i in range(7) ]

# flag constraint
initial_flag = "4545584c831918231c404e35265b03672c713248373f30393a473e34214f5d694a28270a56".decode('hex')
for k in range(len(initial_flag)):
    s.add(flag[k] == ord(initial_flag[k]))

# key constraint
for i in range(len(key)):
    s.add(0 <= key[i])
    s.add(key[i] < 37)
for i in range(0, len(key)-2):
    s.add(key[i] <= key[i+2])

# relation constraint
for k in range(len(flag)):
    for i in range(len(key)):
        if i % 2 == 0:
            flag[k] += k * key[i] % 37
        else:
            flag[k] -= k * key[i] % 37
    flag[k] %= 256

# result constraint
for k, c in list(enumerate('ECTF{')) + [(len(flag)-1, '}')]:
    s.add(flag[k]  == ord(c))
for k in range(len(flag)):
    s.add(0x20 <= flag[k])
    s.add(flag[k] <= 0x7e)

r = s.check()
if r == sat:
    m = s.model()
else:
    print 'unsat'
    exit(1)

print ','.join([str(m[n].as_long()) for n in key])
```
