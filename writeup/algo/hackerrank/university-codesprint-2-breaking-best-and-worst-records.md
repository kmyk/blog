---
layout: post
alias: "/blog/2017/02/22/hackerrank-university-codesprint-2-breaking-best-and-worst-records/"
date: "2017-02-22T23:43:52+09:00"
title: "HackerRank University CodeSprint 2: Breaking the Records"
tags: [ "competitive", "writeup", "hackerrank", "codesprint", "university-codesprint" ]
"target_url": [ "https://www.hackerrank.com/contests/university-codesprint-2/challenges/breaking-best-and-worst-records" ]
---

## problem

ある人がゲームで取った得点の列が与えられる。最高得点、最低得点の更新回数をそれぞれ答えよ。

## solution

``` python
#!/usr/bin/env python3
n = int(input())
best, worst = float('-inf'), float('inf')
increased, decreased = -1, -1
for a in map(int, input().split()):
    if best < a:
        best = a
        increased += 1
    if worst > a:
        worst = a
        decreased += 1
print(increased, decreased)
```
