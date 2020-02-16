---
layout: post
redirect_from:
  - /blog/2017/06/22/google-ctf-2017-quals-introspective-crc/
date: "2017-06-22T03:01:06+09:00"
tags: [ "ctf", "writeup", "crypto", "google-ctf", "crc", "linarity" ]
---

# Google Capture The Flag 2017 (Quals): Introspective CRC

## problem

```
$ nc selfhash.ctfcompetition.com 1337
0101010101010101010101010101010101010101010101010101010101010101010101010101010101 
Give me some data: 
Check failed.
Expected: 
    crc_82_darc(data) == int(data, 2)
Was:
    3885922831092520253093991L
    1611901092819505566274901L
```

## solution

``` python
f = lambda x: crc_82_darc(bin(x)[2 :].zfill(82))
```

とすると、この関数$f : 2^{82} \to 2^{82}$の不動点を探せばよい。
特に、$x \mapsto f(x) \oplus f(0)$は線形。

したがって、線形な関数$g(x) = f(x) \oplus f(0) \oplus x$に対し$g(x) = f(0)$となるような自然数$x \lt 2^{82}$を探せばよい。
線形性より基底$\\{ 1, 2, 4, \dots, 2^k, \dots, 2^{81} \\}$に対する$g(1), g(2), g(4), \dots, g(2^k), \dots, g(2^{81})$だけ見ればよい。
特に$2^{81}$をvector空間と見て一次変換$g$を行列表示$A = g$して$y = f(0)$とおけば、単に$y = Ax$を解くだけとなる。
Gaussの消去法により$x$は得られ、これが答え。

`CTF{i-hope-you-like-linear-algebra}`

## implementation

``` c++
#!/usr/bin/env python3
import copy
import random

def gaussian_elimination(a, b):
    n = len(a)
    a = copy.deepcopy(a)
    b = copy.deepcopy(b)
    for y in range(n):
        pivot = y
        while pivot < n and not a[pivot][y]:
            pivot += 1
        if pivot == n:
            continue
        assert pivot < n
        a[y], a[pivot] = a[pivot], a[y]
        b[y], b[pivot] = b[pivot], b[y]
        assert a[y][y] == 1
        for ny in range(n):
            if ny != y and a[ny][y]:
                for x in range(y+1, n):
                    a[ny][x] ^= a[y][x]
                b[ny] ^= b[y]
    return b

# crc_82_darc
n = 82
def crc_82_darc(data):
    poly = 0x220808a00a2022200c430
    c = 0
    for i, data_i in enumerate(data):
        c ^= ord(data_i)
        for _ in range(8):
            low = c & 1
            c >>= 1
            if low:
                c ^= poly
    return c

# make a linear function
def f(x):
    data = bin(x)[2 :].zfill(n)
    return crc_82_darc(data)
def g(x):
    return f(x) ^ f(0) ^ x
def fmt(x):
    return bin(x)[2 :].zfill(n)
assert g(0) == 0
for _ in range(100):
    x = random.randint(0, 2 ** n - 1)
    y = random.randint(0, 2 ** n - 1)
    assert g(x) ^ g(y) == g(x ^ y)

# solve the matrix
a = [ [ None for _ in range(n) ] for _ in range(n) ]
for y in range(n):
    for x in range(n):
        a[y][x] = int(fmt(g(2 ** x))[y])
b = list(map(int, fmt(f(0))))
c = gaussian_elimination(a, b)

# done
x = int(''.join(map(str, reversed(c))), 2)
print(fmt(x))
assert f(x) == x
```
