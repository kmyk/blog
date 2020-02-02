---
layout: post
alias: "/blog/2016/05/01/hackerrank-world-codesprint-april-jumping-on-the-clouds/"
title: "HackerRank World Codesprint April: Jumping on the Clouds"
date: 2016-05-01T12:20:10+09:00
tags: [ "competitive", "writeup", "hackerrank", "world-codesprint" ]
"target_url": [ "https://www.hackerrank.com/contests/world-codesprint-april/challenges/jumping-on-the-clouds" ]
---

## solution

Simulate it greedily. $O(N)$.

If you can jump to $i+2$-th cloud, then do it, else jump to $i+1$-th one.

## implementation

``` python
#!/usr/bin/env python3
n = int(input())
a = list(map(int,input().split()))
ans = 0
i = 0
while i < n-1:
    i = min(i+2, n-1)
    if a[i] == 1:
        i -= 1
    ans += 1
print(ans)
```
