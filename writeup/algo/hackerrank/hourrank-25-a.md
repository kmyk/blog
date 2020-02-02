---
layout: post
alias: "/blog/2018/01/03/hackerrank-hourrank-25-a/"
title: "HackerRank HourRank 25: A. Constructing a Number"
date: "2018-01-03T11:18:30+09:00"
tags: [ "competitive", "writeup", "hackerrank", "hourrank" ]
"target_url": [ "https://www.hackerrank.com/contests/hourrank-25/challenges/constructing-a-number" ]
---

## problem

数列が与えられる。数列中の数を数字列と見てこれを全て繋げて適当に並び換え、$3$の倍数にできるか。

## implementation

``` python
#!/usr/bin/env python3
for _ in range(int(input())):
    n = int(input())
    a = list(map(int, input().split()))
    acc = 0
    for a_i in a:
        for c in str(a_i):
            acc += int(c)
    print(['No', 'Yes'][acc % 3 == 0])
```
