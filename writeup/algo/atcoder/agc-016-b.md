---
layout: post
alias: "/blog/2017/08/09/agc-016-b/"
date: "2017-08-09T22:21:12+09:00"
title: "AtCoder Grand Contest 016: B - Colorful Hats"
tags: [ "competitive", "writeup", "atcoder", "agc" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc016/tasks/agc016_b" ]
---

丁寧さが必要。

## solution

-   全体の帽子の色の種類数を$A$とする
-   自分の帽子以外は見えているのだから$a\_i = A-1, A$ for all $i$でなければならない
-   $a\_i$が全て等しいかどうかで場合分け
    -   $A-1$が$x \ge 1$個、$A$が$N - x \ge 1$個あるとき
        -   $A = \max a\_i$
        -   $1$個しかない色が$x$個、$2$個以上ある色が$A - x$個
        -   $A - x \ge 1$でなければならない
        -   $x + 2(A - x) \le N$でなければならない
        -   以上を満たすならよい
    -   全て等しい場合
        -   以下を試してどちらか成り立てばよい
        -   $a\_i = A - 1$ for all $i$なら、$N$
        -   $a\_i = A$ for all $i$なら、$A$色がそれぞれ$2$個以上ずつあるので$2A \le N$

## implementation

``` python
#!/usr/bin/env python3
def solve(a):
    a = sorted(a)
    if a[0] + 2 <= a[-1]:
        return False
    if a[0] == a[-1]:
        return a[0] + 1 == len(a) or 2 * a[-1] <= len(a)
    x = a.count(a[0])
    return x < a[-1] and x + 2 * (a[-1] - x) <= len(a)
n = int(input())
a = list(map(int, input().split()))
print(['No', 'Yes'][solve(a)])
```
