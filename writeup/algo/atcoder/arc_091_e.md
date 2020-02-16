---
layout: post
date: 2018-10-12T01:26:19+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "construction", "construction" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc091/tasks/arc091_c" ]
redirect_from:
  - /writeup/algo/atcoder/arc-091-e/
---

# AtCoder Regular Contest 091: E - LISDL

## 解法

### 概要

構築。十分条件が必要条件であることを信じる。
$O(N)$ あるいは $O(N \log N)$。

### 詳細

まず $N, A, B$ の間の自明な関係を眺めよう。
$N$が小さいときは下の図のような形の列が最適なので$A + B - 1 \le N$が必要。

```
B
  B
    B
      B
       *
     A
   A
 A
```

$N$が大きいときが困難。
$A = B = 1$ で $N = 10^5$ などでは当然不可能なので何らかの不等式がある。
上に書いた図からこれを探すべくいくつか試すと、ある種のブロック化が有効であることが分かる。
つまり次の図のような形。

```
     |     |     |...
-----+-----+-----+---
     |     |B    |
     |     | B   |
     |     |  B  |
     |     |   B |
     |     |    B|
-----+-----+-----+
     |B    |
     | B   |
     |  B  |
     |   B |
     |    B|
-----+-----+
B    |
 B   |
  B  |
   B |
    B|
```

これにより不等式 $N \le AB$ が十分条件であることが分かる。
これはおそらく必要条件でもあるので、実装すれば通る。

## 実装

``` python
#!/usr/bin/env python3

def solve(n, a, b):
    if a + b - 1 > n:
        return [ -1 ]
    if a * b < n:
        return [ -1 ]

    # construct in Z^2
    xs = []
    xs += [ (0, - j) for j in range(b) ]
    for i in range(1, a):
        xs += [ (i, 0) ]
        j = 1
        while j < b and len(xs) + (a - i - 1) < n:
            xs += [ (i, - j) ]
            j += 1

    # coordinate compression
    f = {}
    for x in sorted(xs):
        k = len(f)
        f[x] = k
    return [ f[x] + 1 for x in xs ]

print(*solve(*map(int, input().split())))

```
