---
layout: post
alias: "/blog/2016/12/24/xmas-contest-2016-a/"
date: "2016-12-24T23:33:39+09:00"
title: "Xmas Contest 2016: A - Array Sum"
tags: [ "competitive", "writeup", "atcoder", "xmas-contest", "reactive" ]
"target_url": [ "https://beta.atcoder.jp/contests/xmascon16noon/tasks/xmascon16_a" ]
---

高難度だった。$1$完。

## solution

整数$N$を$2$羃$p^i \le N$の線形結合で表す問題。特にその係数の絶対値の総和が最小になるものを構成する。$O(\log N)$。

具体的な区間は忘れ、その長さだけ考えよう。
$p^i$を足したり引いたりしてちょうど$N$にすればよい。
ただし引き算を使う場合があることに注意。例えば$(10001111)\_2$であれば$(10001111)\_2 = (10000000)\_2 + (10000)\_2 - (1)\_2$とした方が速い。
さらに$p^i \le N$の制約もある。$(11111111)\_2 = 2 \cdot (10000000)\_2 - (1)\_2$となる。
具体的な区間を思い出して、その構成はこれを計算するときについでに計算する。

## implementation

``` python
#!/usr/bin/env python3
import sys
def mapshift(n, xs, sign=+1):
    return [ (s*sign, l+n, r+n) for s, l, r in xs ]
def minlen(a, b):
    if a is None:
        return b
    if b is None:
        return a
    return min((len(a), a), (len(b), b))[1]
def solve(n, limit=None):
    assert n >= 0
    if limit is None:
        limit = n
    if n == 0:
        return []
    result = None
    i = len(bin(n)[2 :]) - 1
    if n - 2**i < n:
        result = minlen(result, [ (+1, 0, 2**i) ] + mapshift(2**i, solve(n - 2**i, limit=limit)))
    if 2**(i+1) - n  < n:
        if n == limit:
            result = minlen(result, [ (+1, 0, 2**i) ] + [ (+1, n - 2**i, n) ]+ mapshift(n - 2**i, solve(2**i * 2 - n, limit=limit), sign=-1))
        else:
            result = minlen(result, [ (+1, n - 2**(i+1), n) ] + mapshift(n - 2**(i+1), solve(2**(i+1) - n, limit=limit), sign=-1))
    return result

n = int(input())
acc = 0
for sign, l, r in solve(n):
    print('?', l, r)
    sys.stdout.flush()
    acc += sign * int(input())
print('!', acc)
sys.stdout.flush()
```
