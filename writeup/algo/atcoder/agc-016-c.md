---
layout: post
alias: "/blog/2017/08/09/agc-016-c/"
date: "2017-08-09T21:29:13+09:00"
title: "AtCoder Grand Contest 016: C - +/- Rectangle"
tags: [ "competitive", "writeup", "atcoder", "agc" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc016/tasks/agc016_c" ]
---

$h, w$おきに$- hw$置いてそれ以外$1$にすればいいのではと思ったが、ぜんぜんそんなことはなかった。

## solution

$w \mid W \land h \mid H$なら`No`。そうでなければ`Yes`。
$w \mid W$とし$H = h = 1$と見做して解いてその結果を$H$行並べればよい。
十分大きい数$A$を固定して$0, w, 2w, \dots$項目を$A$とし$w-1, 2w-1, 3w-1, \dots$項目を$-A-1$とする。
総和は$\mathrm{ceil}(\frac{W}{w})A + \mathrm{floor}(\frac{W}{w})(- A - 1)$となる。$O(HW)$。

## implementation

``` python
#!/usr/bin/env python3
H, W, h, w = map(int, input().split())
if W % w == 0 and H % h == 0:
    print('No')
else:
    swapped = False
    if W % w == 0:
        H, W, h, w, swapped = W, H, w, h, True
    a = [ [ 0 for _ in range(W) ] for _ in range(H) ]
    for y in range(H):
        for x in range(0, W, w):
            a[y][x] = W
        for x in range(w - 1, W, w):
            a[y][x] = - W - 1
    if swapped:
        H, W, h, w = W, H, w, h
        b = a
        a = [ [ 0 for _ in range(W) ] for _ in range(H) ]
        for y in range(H):
            for x in range(W):
                a[y][x] = b[x][y]
    print('Yes')
    for y in range(H):
        print(*a[y])
```
