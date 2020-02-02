---
layout: post
alias: "/blog/2018/04/05/google-code-jam-2017-round-1c-a/"
title: "Google Code Jam 2017 Round 1C: A. Ample Syrup"
date: "2018-04-05T00:17:35+09:00"
tags: [ "competitive", "writeup", "gcj", "greedy" ]
"target_url": [ "https://codejam.withgoogle.com/codejam/contest/dashboard?c=3274486#s=p0" ]
---

## solution

上面の広さの最大値 + 側面の広さの総和 が答え。
上面のために使うひとつを決めれば残りは側面が広い順に貪欲でよい。$O(n \log n)$。

## note

-   部会の後に後輩氏宅で解いた
-   後輩氏が$H\_i \cdot R\_i$するところでoverflowしてた

## implementation

``` python
#!/usr/bin/env python3
import math
t = int(input())
for i in range(t):
    n, k = map(int, input().split())
    pancakes = []
    for _ in range(n):
        r, h = tuple(map(int, input().split()))
        pancakes += [ {
            'r': r,
            'h': h,
            'side': 2 * math.pi * r * h,
            'top': math.pi * r ** 2,
        } ]
    pancakes.sort(key=lambda a: a['side'], reverse=True)
    answer = 0
    top  = max(- math.inf, - math.inf, *map(lambda a: a['top'],  pancakes[: k - 1]))
    side = sum(map(lambda a: a['side'], pancakes[: k - 1]))
    for a in pancakes[k - 1 :]:
        answer = max(answer, max(top, a['top']) + side + a['side'])
    print('Case #%d: %.12f' % (i + 1, answer))
```
