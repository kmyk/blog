---
layout: post
alias: "/blog/2015/11/10/arc-007-d/"
date: 2015-11-10T21:31:17+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "corner-cases" ]
---

# AtCoder Regular Contest 007 D - 破れた宿題

発想は簡単だけどコーナーケースが多い問題。
やれば通せる。

<!-- more -->

## [D - 破れた宿題](https://beta.atcoder.jp/contests/arc007/tasks/arc007_4) {#d}

### 問題

数字列が与えられる。
これはある等差数列から、始めのいくつかの項を取りだし、文字列として結合し、先頭と末尾からいくつかの文字を落としたものである。
初項に由来する文字は必ず存在する。
初項、公差を復元せよ。
初項、公差は正の整数であり、 複数考えられる場合は初項 $\to$ 公差の順に最小化し最小のものを答えよ。

### 解法

初項を適当に決めても第2項を十分大きとれば要件を満たすので、まず初項だけ決定してよい。
小さいほど良いので、文字列の第1文字目のみを初項とする。ただし、それが`0`である場合や、残りの文字列が`0`から始まる場合に注意する。

次は公差である。
第2項の桁数に関して下から順に見ていけばよい。
ただし、初項決定時点で残りの文字列が空である場合、第2項の桁数が残りの文字列の長さより長くなる場合、特にその中でも、残りの文字列が初項のprefixになっている場合に注意(e.g. 入力`10010`の場合、公差`1`が正解)。

### 実装

``` python
#!/usr/bin/env python3
s = input()
if s[0] == '0':
    a = '1'
else:
    a, s = s[0], s[1:]
l = next(i for i,v in enumerate(s + '!') if v != '0')
a = int(a + '0' * l)
s = s[l:]
assert a >= 1
assert not len(s) or s[0] != '0'
if len(s):
    for l in range(len(str(a)), len(s)+1):
        b, t = int(s[:l]), s[l:]
        if b <= a:
            continue
        d = b - a
        while len(t):
            c = b + d
            if len(t) < len(str(c)):
                t += str(c)[- len(str(c)) + len(t) :]
            if t.startswith(str(c)):
                t = t.replace(str(c), '', 1)
            else:
                d = 0
                break
            b = c
        if d:
            break
    else:
        if str(a) != s and str(a).startswith(s):
            b = a + 1
        else:
            b = int(s)
            while b <= a:
                b *= 10
        d = b - a
else:
    d = 1
assert d >= 1
print(a, d)
```
