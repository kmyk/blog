---
layout: post
alias: "/blog/2017/12/08/code-blue-ctf-2017-common-modulus-1/"
title: "CODE BLUE CTF 2017: Common Modulus 1"
date: "2017-12-08T10:07:09+09:00"
tags: [ "ctf", "writeup", "crypto", "code-blue-ctf", "rsa", "gcd" ]
"target_url": [ "https://ctftime.org/task/4872" ]
---

## problem

RSAの公開鍵$(n, e\_1), (n, e\_2)$と同じ$m$に対する暗号文$c\_1, c\_2$が与えられる。
$m$を求めよ。
ただし$e\_1, e\_2$は素数。

## solution

Euclidの互除法をする。
$e\_2 = qe\_1 + r$とする互除法に合わせて$c\_2 \cdot c\_1^{- q} \equiv m^r$のようにしていけば$m^{\mathrm{gcd}(e\_1, e\_2)}$が求まる。
$e\_1, e\_2$は素数なので自明に互いに素つまり$\mathrm{gcd}(e\_1, e\_2) = 1$なので$m$が得られる。

## implementation

``` python
#!/usr/bin/env python3
import ast
import gmpy2
from Crypto.Util.number import long_to_bytes

# input
with open('transcript.txt') as fh:
    n, e1 = ast.literal_eval(fh.readline().split(': ')[1].replace('L', ''))
    c1 = int(fh.readline().split('=')[1])
    fh.readline()
    n, e2 = ast.literal_eval(fh.readline().split(': ')[1].replace('L', ''))
    c2 = int(fh.readline().split('=')[1])

# Euclidean algorithm
assert e1 < e2
while e1:
    c1, c2 = (c2 * pow(gmpy2.invert(c1, n), e2 // e1, n) % n), c1
    e1, e2 = e2 % e1, e1
assert e2 == 1
m = c2

# output
print(long_to_bytes(m).decode())
```
