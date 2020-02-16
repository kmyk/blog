---
layout: post
redirect_from:
  - /blog/2016/05/23/hackerrank-may-world-codesprint-compare-the-triplets/
date: 2016-05-23T01:49:33+09:00
tags: [ "competitive", "writeup", "hackerrank", "world-codesprint" ]
"target_url": [ "https://www.hackerrank.com/contests/may-world-codesprint/challenges/compare-the-triplets" ]
---

# HackerRank May World CodeSprint: Compare the Triplets

## problem

$A = (a_0, a_1, a_2)$と$B = (b_0, b_1, b_2)$が与えられる。
$a_i \gt b_i$なもの、$a_i \lt b_i$なものをそれぞれ数えよ。

## implementation

``` python
#!/usr/bin/env python3
xs = list(map(int,input().split()))
ys = list(map(int,input().split()))
a = sum(map(lambda x, y: x > y, xs, ys))
b = sum(map(lambda x, y: x < y, xs, ys))
print(a, b)
```
