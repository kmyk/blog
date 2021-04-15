---
redirect_from:
  - /writeup/ctf/2018/midnight-sun-ctf-2018-finals-badchair/
layout: post
date: "2018-06-25T11:39+09:00"
tags: [ "ctf", "writeup", "midnight-sun-ctf", "crypto", "shamirs-secret-sharing", "gaussian-elimination" ]
"target_url": [ "https://ctftime.org/event/635" ]
---

# Midnight Sun CTF Finals 2018: Badchair

## problem

shares = 9 / threshold = 5 のShamir秘密共有した結果から4個だけ与えられるので割れ

## solution

There is a polynomial $f\_k(x) = a\_4 x^4 + a\_3 x^3 + a\_2 x^2 + a\_1 x + k$ on $GF(2^8)$.
For each char $k$ of the flag, random $8$ points $x\_0, x\_1, \dots, x\_7$ are chosen, and values $f(x\_0), f(x\_1), \dots, f(x\_7)$ are computed. Then, $4$ of them, $f(x\_0), f(x\_1), \dots, f(x\_3)$ is given.

Therefore, these polynomials are the same up to constants. 
If you can guess the flag is like `midnight{???????????????????}`, there is enough information ($4 \times 10$ points) to fix $a\_4, \dots, a\_1$, with the gaussian elimination.

## implementation

``` python
# Python Version: 3.x
import os
import json 
import base64

FLAG = 'midnight{???????????????????}'
from point import Point
numshares = 9
threshold = 5

with open('shares.txt') as fh:
    shares = []
    for line in fh:
        shares += [ json.loads(line) ]
    assert len(shares) == threshold - 1 == 4


def point_pow(x, n):
    y = Point(1)
    while n:
        y *= Point(x)
        n -= 1
    return y

def point_negate(x):
    return x

def gaussian_elimination(f, v):
    n = len(v)
    for y in range(n):
        pivot = y
        while pivot < n and not f[pivot][y].value:
            pivot += 1
        assert pivot < n
        f[y], f[pivot] = f[pivot], f[y]
        v[y].__idiv__(f[y][y])
        for x in range(y + 1, n):
            f[y][x].__idiv__(f[y][y])
        f[y][y] = Point(1)
        for ny in range(n):
            if ny != y:
                v[ny] += point_negate(f[ny][y] * v[y])
                for x in range(y + 1, n):
                    f[ny][x] += point_negate(f[ny][y] * f[y][x])
                f[ny][y] = Point(0)

def apply_poly(coeffs, coord):
    B = Point(1)
    S = Point(0)
    X = Point(coord)
    for coeff in coeffs:
        S += (B * Point(coeff))
        B *= X
    return S.value


graph = []
for i, char in enumerate(FLAG):
    if char == '?':
        continue
    for j in range(4):
        x = base64.b64decode(shares[j]['split'][0])[i]
        y = base64.b64decode(shares[j]['split'][1])[i]
        graph += [ ( x, y ^ ord(char)) ]

matrix = []
vector = []
for x, y in graph[: 4]:
    matrix += [ [ point_pow(x, 1), point_pow(x, 2), point_pow(x, 3), point_pow(x, 4) ] ]
    vector += [ Point(y) ]
gaussian_elimination(matrix, vector)
base_poly = [ x.value for x in vector ]

flag = ''
for i, char in enumerate(FLAG):
    j = 0
    x = base64.b64decode(shares[j]['split'][0])[i]
    y = base64.b64decode(shares[j]['split'][1])[i]
    c = chr(apply_poly([ 0 ] + base_poly, x) ^ y)
    if char != '?':
        assert c == char
    print(i, ':', c)
    flag += c
print(flag)
```
