---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc-047-c/
  - /blog/2016/02/23/arc-047-c/
date: 2016-02-23T07:07:27+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "factoradic", "permutation" ]
---

# AtCoder Regular Contest 047 C - N!÷K番目の単語

本番は出ていたけど少し覗いただけで、Bに時間を取られて(結局解けなかった)触れなかった問題。
こちらをやっていれば解けていたかもしれない。

## [C - N!÷K番目の単語](https://beta.atcoder.jp/contests/arc047/tasks/arc047_c)

### 問題

階乗進数。$O(N)$。

$\frac{1}{K}\cdot N! - 1$の階乗進数表記を求める問題。
連分数展開の要領で整数に直していく。

$\frac{1}{K} \cdot N! = \frac{N}{K} \cdot (N-1)! = \lfloor \frac{N}{K} \rfloor \cdot (N-1)! + \frac{(N \bmod K)(N - 1)}{K} \cdot (N-2)! = \dots$

### 実装

`math.gcd`はversion 3.5かららしい。REした。

``` python
#!/usr/bin/env python3
def math_gcd(a, b):
    a, b = min(a, b), max(a, b)
    while a > 0:
        a, b = b % a, a
    return b
# input
n, k = map(int,input().split())
# make factoradic number 1/k*n!
ds = [0] * n
p, q = 1, k
e = n
while e-1 >= 1:
    p *= e
    e -= 1
    ds[e] = p // q
    p %= q
    r = math_gcd(p, q)
    p //= r
    q //= r
# decrement
for i in range(n):
    if ds[i]:
        ds[i] -= 1
        break
    else:
        ds[i] = i
# decode factoradic
cs = list(range(1,n+1))
for d in reversed(ds):
    print(cs[d])
    del cs[d]
```
