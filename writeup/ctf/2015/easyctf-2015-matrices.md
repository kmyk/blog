---
layout: post
alias: "/blog/2016/09/02/easyctf-2015-matrices/"
date: "2016-09-02T15:30:25+09:00"
title: "EasyCTF 2015: Matrices"
tags: [ "ctf", "writeup", "crypto", "easyctf", "hill-cipher" ]
"target_url": [ "https://github.com/ctfs/write-ups-2015/tree/master/easyctf-2015/cryptography/matrices" ]
---

CBC modeな感じのHill暗号ぽいやつ。
blockごとに集めてきてmodularな逆行列を含む行列演算で鍵がでて、同様にやれば複合化できる。
`easyctf{4b5+r4C+10N}`。

``` python
#!/usr/bin/env python3

import operator
import numpy as np
import gmpy2

def random(m, n):
    return np.random.randint(1, 254+1, size=(m, n))

def modinv(a_f, m):
    f = np.copy(a_f)
    assert isinstance(f, np.ndarray)
    assert isinstance(m, int)
    n = a_f.shape[0]
    g = np.identity(n, dtype=int)
    for i in range(n):
        for j in range(i+1,n):
            try:
                gmpy2.invert(int(f[j,i]), m)
                f[i], f[j] = np.copy(f[j]), np.copy(f[i])
                g[i], g[j] = np.copy(g[j]), np.copy(g[i])
                break
            except:
                pass
        inv = int(gmpy2.invert(int(f[i,i]), m))
        f[i] = f[i] * inv % m
        g[i] = g[i] * inv % m
        for j in range(n):
            if j != i:
                p = f[j,i]
                f[j] = (f[j] - f[i] * p) % m
                g[j] = (g[j] - g[i] * p) % m
    assert np.array_equal(f, np.identity(n, dtype=int))
    assert np.array_equal(a_f.dot(g) % m, np.identity(n, dtype=int))
    assert isinstance(g, np.ndarray)
    return g

def encrypt(message, key):
    assert isinstance(message, bytes)
    assert isinstance(key, np.ndarray)
    n = len(key)
    buf = [ 0 ] * n
    result = b'';
    for i in range(0, len(message), n):
        for j in range(n):
            if i+j < len(message):
                buf[j] ^= message[i+j]
            else:
                buf[j] = 0
        buf = (key.dot(np.array(buf)) % 251).tolist()
        result += bytes(buf)
    assert isinstance(result, bytes)
    return result

def crack(message, result, n):
    assert isinstance(message, bytes)
    assert isinstance(result, bytes)
    assert isinstance(n, int)
    xs = []
    ys = []
    for i in range(n):
        xs += [ list(map(operator.xor, message[i*n : (i+1)*n], (b'\0' * n + result)[i*n : (i+1)*n])) ]
        ys += [ list(result[i*n : (i+1)*n]) ]
    xs = np.transpose(np.array(xs))
    ys = np.transpose(np.array(ys))
    key = ys.dot(modinv(xs, 251)) % 251
    assert np.array_equal(key.dot(xs) % 251, ys)
    assert isinstance(key, np.ndarray)
    return key

def decrypt(result, key):
    assert isinstance(result, bytes)
    assert isinstance(key, np.ndarray)
    n = len(key)
    inv = modinv(key, 251)
    xs = []
    for i in range(0, len(result), n):
        y = np.array(list(result[i : i+n]))
        x = inv.dot(y) % 251
        assert np.array_equal(key.dot(x) % 251, y)
        xs += x.tolist()
    message = bytes(map(operator.xor, xs, b'\0' * n + result))
    assert isinstance(message, bytes)
    return message

n = 16
with open('message1') as fh:
    message1 = fh.buffer.read()
with open('output1') as fh:
    output1 = fh.buffer.read()
with open('output2') as fh:
    output2 = fh.buffer.read()

key = crack(message1, output1, n)
assert encrypt(message1, key) == output1
print(decrypt(output2, key))
```
