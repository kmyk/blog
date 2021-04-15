---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/550/
  - /blog/2017/07/29/yuki-550/
date: "2017-07-29T00:10:15+09:00"
tags: [ "competitive", "writeup", "yukicoder", "binary-search", "math", "differential" ]
"target_url": [ "https://yukicoder.me/problems/no/550" ]
---

# Yukicoder No.550 夏休みの思い出（１）

一般に$n$次関数でも解けそう。

## solution

$3$次関数なので単調とは限らないが、解の近くに限定すると単調。
うまく二分探索。
解の範囲の大きさ$L$に対し$O\log L)$。

具体的な解$\alpha, \beta, \gamma$に対し$\alpha \lt x\_l \lt \beta \lt x\_r \lt \gamma$となるような$x\_l, x\_r$を求めて、区間ごとに二分探索する。
$x\_l, x\_r$を求めるのは再帰的にする。
与えられた関数$f(x) = x^3 + ax^2 + bx + c$に対し$f(x) = 0$な$x$を求めるのが主問題だが、導関数$f'(x)$に対してその解$x\_l, x\_r$を求めると、これは上の条件を満たす。
$f'(x)$の解を求めるのは$2$回微分$f''(x)$の解$x\_m$が$x\_l \lt x\_m \lt x\_r$となることから同様にする。
$f''(x)$は直接的に解けるのでこれでよい。

## implementation

``` python
#!/usr/bin/env python3
def binsearch_float(l, r, pred): # [l, r)
    assert l < r
    for _ in range(100):
        m = (l + r) / 2
        if pred(m):
            r = m
        else:
            l = m
    return r

a, b, c = map(int, input().split())
f = lambda x: x ** 3 + a * x ** 2 + b * x + c
df = lambda x: 3 * x ** 2 + 2 * a * x + b
x2 = - a / 3
x1l = binsearch_float(- 10 ** 12, x2, lambda x: df(x) < 0)
x1r = binsearch_float(x2, + 10 ** 12, lambda x: df(x) > 0)
x0a = binsearch_float(- 10 ** 12, x1l, lambda x: f(x) > 0)
x0b = binsearch_float(x1l,        x1r, lambda x: f(x) < 0)
x0c = binsearch_float(x1r, + 10 ** 12, lambda x: f(x) > 0)

xs = set()
for x0 in [ x0a, x0b, x0c ]:
    for delta in range(-10, 11):
        if f(int(x0) + delta) == 0:
            xs.add( int(x0) + delta )
print(*sorted(xs))
```
