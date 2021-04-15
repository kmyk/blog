---
layout: post
redirect_from:
  - /writeup/algo/codeforces/615-e/
  - /blog/2016/01/09/cf-615-e/
date: 2016-01-09T04:20:11+09:00
tags: [ "competitive", "writeup", "codeforces", "binary-search" ]
---

# Codeforces Round #338 (Div. 2) E. Hexagons

C,Dで忙しくて開けなかった問題。EなのにC,Dより簡単だった。

## [E. Hexagons](http://codeforces.com/contest/615/problem/E) {#e}

### 解法

原点を中心とする同心の六角形上をぐるぐる回る。
まず何周目かを二分探索し、どの辺の上にいるか、その辺の上でどの位置にいるかを求めれば、座標が計算できる。

### 実装

``` python
#!/usr/bin/env python3
def binsearch(p, l, r): # (l,r], return the smallest n which p holds
    while l+1 != r:
        m = (l + r) // 2
        if p(m):
            r = m
        else:
            l = m
    return r
n = int(input())
if n == 0:
    print(0, 0)
else:
    i = binsearch(lambda i: n <= 3*i*(i+1), 0, 10**18)
    acc = 3*(i-1)*i
    j = binsearch(lambda j: n <= acc + i*(j+1), -1, 6)
    k = n - acc - i*j - 1
    dy = [ 0, 2,  2,  0, -2, -2 ]
    dx = [ 2, 1, -1, -2, -1,  1 ]
    y = dy[(j+1)%6] + dy[j]*(i-1) + dy[(j+2)%6]*k
    x = dx[(j+1)%6] + dx[j]*(i-1) + dx[(j+2)%6]*k
    print(x, y)
```
