---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc_054_b/
  - /writeup/algo/atcoder/arc-054-b/
  - /blog/2016/05/25/arc-054-b/
date: 2016-05-25T19:40:56+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "ternary-search" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc054/tasks/arc054_b" ]
---

# AtCoder Regular Contest 054 B - ムーアの法則

## solution

求めるのは、与えられた$P$に対し、

-   $\min f(x) = x + \frac{p}{2^{\frac{x}{1.5}}}$
-   $\text{sub to} \; $x \ge 0$

下に凸っぽさがあるので、三分探索する。
初期区間は適当につくる。

## implementation

``` python
#!/usr/bin/env python3
p = float(input())
def f(x):
    return x + p / pow(2, x / 1.5)
def ternary_search():
    l = 0
    r = 0
    while f(r) > f(r+1):
        r += 1
    r += 1
    for _ in range(1000):
        ml = (l + l + r) / 3
        mr = (l + r + r) / 3
        if f(ml) < f(mr):
            r = mr
        else:
            l = ml
    return f(l)
print(ternary_search())
```
