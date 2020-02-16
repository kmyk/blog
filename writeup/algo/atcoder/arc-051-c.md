---
layout: post
redirect_from:
  - /blog/2016/04/22/arc-051-c/
date: 2016-04-22T18:44:45+09:00
tags: [ "competitive", "writeup", "atcoder", "arc" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc051/tasks/arc051_c" ]
---

# AtCoder Regular Contest 051 C - 掛け算

## solution

対数をとって、いくらかを残してまとめて処理する。$O(N \log \max_i a_i)$。

比較が必要であるが数が大きくなりすぎる問題に関して。
対数をとった上で実際に処理を行えばよい。

掛け算をする回数が多い問題に関して。
初期値$a_i$は処理後の結果$a_i \cdot A^b_i$にほとんど影響しない。
$a_i$は高々$10^9$であり、$A \ge 2$とすると高々$32$回$A$を掛ければ初期値の差は埋まる。
なので$B$の内の$32N$回程を残してそれ以外は、$N$個の項に均等な回数掛けることになる。
残したいくらかの回数は、毎回最小値に$A$を掛けてやればよい。

## implementation

$A = 1$の場合は別になるかなと思っていたが、処理するのを忘れたまま提出したら通ってしまった。

``` python
#!/usr/bin/env python3
import math
lim = 1000
mod = int(1e9+7)
# input
n, a, b = map(int,input().split())
xs = list(map(int,input().split()))
# calc
lim = min(b, lim)
t = (b - lim) // n
ys = [math.log(x) + math.log(a) * t for x in xs]
zs = [t] * n
for _ in range(b - t * n): # at most lim times
    i = ys.index(min(ys))
    ys[i] += math.log(a)
    zs[i] += 1
# output
ixs = list(range(n))
ixs.sort(key=lambda i: ys[i])
for i in ixs:
    print(xs[i] * pow(a, zs[i], mod) % mod)
```
