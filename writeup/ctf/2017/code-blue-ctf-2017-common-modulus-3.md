---
layout: post
redirect_from:
  - /blog/2017/12/08/code-blue-ctf-2017-common-modulus-3/
date: "2017-12-08T10:07:35+09:00"
tags: [ "ctf", "writeup", "crypto", "code-blue-ctf", "rsa", "gcd", "coppersmith-attack" ]
"target_url": [ "https://ctftime.org/task/4874" ]
---

# CODE BLUE CTF 2017: Common Modulus 3

## problem

[Common Modulus 2](/blog/2017/12/08/code-blue-ctf-2017-common-modulus-2/)と同様。ただし$e\_1, e\_2$への乗数は$3$でなく$17$、$m$はflagそのままでなくpadding付き。

## solution

Coppersmith's attack。

非想定解として$m \cdot k^{-1}$の$17$乗根を取るというのがあったらしい。paddingが単に$k$を乗算しているだけであり$\mathrm{FLAG}^17 \lt N$なので求まってしまう。

## implementation

``` python
#!/usr/bin/env sagemath
import ast
from Crypto.Util.number import long_to_bytes, bytes_to_long

# input
with open('transcript.txt') as fh:
    n, e1 = ast.literal_eval(fh.readline().split(': ')[1].replace('L', ''))
    c1 = Zmod(n)(fh.readline().split('=')[1])
    fh.readline()
    n, e2 = ast.literal_eval(fh.readline().split(': ')[1].replace('L', ''))
    c2 = Zmod(n)(fh.readline().split('=')[1])

# Euclidean algorithm
assert e1 < e2
while e1:
    c1, c2 = c2 * (1 / c1) ** (e2 / e1), c1
    e1, e2 = e2 % e1, e1
assert e2 == 17

# Coppersmith's attack
PR.<x> = PolynomialRing(Zmod(n))
l = 32
pad = 984
f = (((bytes_to_long('CBCTF{') * 256 ** l + x) * 256 + ord('}')) * 256 ** pad) ** e2 - c2
f = f.monic()
for x in f.small_roots(X=256 ** l, beta=0.5):
    flag = 'CBCTF{' + long_to_bytes(x) + '}'

# output
print(flag)
m = bytes_to_long(flag) * 256 ** pad
assert m ** e2 == c2
```
