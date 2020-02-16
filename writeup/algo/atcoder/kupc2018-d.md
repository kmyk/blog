---
layout: post
date: 2018-10-01T01:23:15+09:00
tags: [ "competitive", "writeup", "atcoder", "kupc", "reactive", "lsb-decryption-oracle-attack", "crypto" ]
"target_url": [ "https://beta.atcoder.jp/contests/kupc2018/tasks/kupc2018_d" ]
---

# Kyoto University Programming Contest 2018: D - ロストテクノロジー

## 解法

### 概要

LSB decryption oracle attackの類似をやるだけ (CTF暗号典型)

### 詳細

次の場合分けを考える:

-   $x \lt q$ の場合: $(x \bmod q) \equiv x \pmod{2}$
-   $\frac{x}{2} \lt q \le x$ の場合: $(x \bmod q) \equiv x - q \pmod{2}$

$\frac{x}{2} \lt q$ な奇数 $q$ を与えてやれば $x \lt q$ かどうかが得られる。
これで二分探索が可能。

## メモ

わりと好き

## 実装

``` python
#!/usr/bin/env python3
import sys

def ask(q):
    print('?', q)
    sys.stdout.flush()
    s = input()
    return int(s == 'odd')

l = 1
r = 10 ** 9 + 1
parity = ask(10 ** 9)
while True:
    m = ((l + r) // 2) | 1
    if not (l < m < r):
        break
    if ask(m) != parity:
        l = m
    else:
        r = m
if l % 2 != parity:
    l += 1
print('!', l)
```
