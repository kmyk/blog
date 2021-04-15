---
layout: post
redirect_from:
  - /writeup/ctf/2017/code-blue-ctf-2017-common-modulus-2/
  - /blog/2017/12/08/code-blue-ctf-2017-common-modulus-2/
date: "2017-12-08T10:07:11+09:00"
tags: [ "ctf", "writeup", "crypto", "code-blue-ctf", "rsa", "gcd", "coppersmith-attack" ]
"target_url": [ "https://ctftime.org/task/4873" ]
---

# CODE BLUE CTF 2017: Common Modulus 2

実質WA。

## problem

[Common Modulus 1](/blog/2017/12/08/code-blue-ctf-2017-common-modulus-1/)と同様。ただし$e\_1, e\_2$は共に素数に$3$を掛けたもの。

## solution

平文$m$に対するCoppersmith's attack。$e = 3$と小さいので$\|x\| \lt N^{\frac{1}{3}}$であり、求まる。

想定解は単に$3$乗根取るだけ。

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
c1, c2 = c2, c1
e1, e2 = e2, e1
assert e1 < e2
while e1:
    c1, c2 = c2 * (1 / c1) ** (e2 / e1), c1
    e1, e2 = e2 % e1, e1
assert e2 == 3

# Coppersmith's attack
PR.<x> = PolynomialRing(Zmod(n))
for l in range(64):
    f = (bytes_to_long('CBCTF{') * 256 ** (l + 1) + x * 256 + ord('}')) ** e2 - c2
    f = f.monic()
    for x in f.small_roots(X=256 ** l, beta=0.5):
        flag = 'CBCTF{' + long_to_bytes(x) + '}'

        # output
        print(flag)
        m = bytes_to_long(flag)
        assert m ** e2 == c2
```
