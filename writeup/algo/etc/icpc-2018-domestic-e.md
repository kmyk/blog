---
layout: post
title: "ACM-ICPC 2018 国内予選: E. 浮動小数点数"
date: 2018-07-10T13:05:00+09:00
tags: [ "competitive", "writeup", "icpc", "floating-point-numbers", "binary-search" ]
"target_url": [ "http://icpc.iisf.or.jp/past-icpc/domestic2018/contest/all_ja.html", "http://icpc.iisf.or.jp/past-icpc/domestic2018/judgedata/E/" ]
---

## solution

誤差が発生する点を二分探索してそこまでをまとめて足す。
実装が重い。
$k$を浮動小数点数のbit数として$O(k \log n)$。

$s \gets s + ka$としたい。
浮動小数点数$a$のbitで$k = 1$の場合には加算結果に影響しないようなbitをすべて倒しておく。
すると$s$の指数部が変化しない範囲では$k$倍してまとめて足せる。
そのような最大$k$は二分探索で決定できる。

多少は遅くなるがPythonの `fractions` に頼ると楽。
bit列で表現された浮動小数点数と本当の有理数の間の変換関数を書いていい感じに。

## note

本番では落とした。私の担当だが、2時間ぐらい使って実装できなかったので完全に戦犯。
`if s == encode(decode(*s) + a): break` の入れ方を間違えていたのが原因ぽい。

解法は今年の模擬国内のGと本質的に同一。

## implementation

``` python
#!/usr/bin/env python3
import sys
from fractions import Fraction

def binsearch(l, r, pred):
    assert l <= r
    l -= 1
    while r - l > 1:
        m = (l + r) // 2
        if pred(m):
            r = m
        else:
            l = m
    return r

def decode(e, f):
    num = int('1' + f, 2)
    if e >= 52:
        return num * 2 ** (e - 52)
    else:
        den = 2 ** (52 - e)
        return Fraction(num, den)

def encode(r):
    assert bin(r.denominator)[2 :].count('1') == 1
    f = bin(r.numerator)[3 :]
    e = - bin(r.denominator)[2 :].count('0')
    if len(f) > 52:
        e += len(f) - 52
        f = f[: 52]
    elif len(f) < 52:
        e -= 52 - len(f)
        f += '0' * (52 - len(f))
    e += 52
    assert len(f) == 52
    return e, f

def trim(s, b):
    for i in reversed(range(52)):
        if b[i] == '1':
            c = b[: i] + '0' + b[i + 1 :]
            s1 = encode(decode(*s) + decode(0, b))
            s2 = encode(decode(*s) + decode(0, c))
            if s1 == s2:
                b = c
    return b

def solve(n, b):
    s = 0, b
    while n >= 1:
        b = trim(s, b)
        a = decode(0, b)
        def pred(k):
            s1 = encode(decode(*s) + k * a)
            return s1[0] > s[0]
        k = binsearch(1, n + 1, pred) - 1
        k = min(n, max(1, k - 3))
        s = encode(decode(*s) + k * a)
        n -= k
        if s == encode(decode(*s) + a):
            break
    e, f = s
    return bin(e)[2 :].zfill(12) + f

while True:
    n = int(input())
    if n == 0:
        break
    b = input()
    print('n =', n, file=sys.stderr)
    print('b =', b, file=sys.stderr)
    ans = solve(n, b)
    print(ans)
    print('ans =', ans, file=sys.stderr)
```
