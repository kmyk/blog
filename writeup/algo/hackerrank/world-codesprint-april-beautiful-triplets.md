---
layout: post
redirect_from:
  - /blog/2016/05/01/hackerrank-world-codesprint-april-beautiful-triplets/
date: 2016-05-01T12:20:29+09:00
tags: [ "competitive", "writeup", "hackerrank", "world-codesprint" ]
"target_url": [ "https://www.hackerrank.com/contests/world-codesprint-april/challenges/beautiful-triplets" ]
---

# HackerRank World Codesprint April: Beautiful Triplets

## problem

狭義単調増加な数列$a$および正整数$d$が与えられる。
$\| \\{ (i, j, k) \mid a_j - a_i = a_k - a_j = d \\} \|$を答えよ。

## solution

Count. You can use a set. $O(N)$.

## implementation

``` python
#!/usr/bin/env python3
n, d = map(int,input().split())
a = list(map(int,input().split()))
s = set(a)
ans = 0
for i in a:
    if i + d in s and i + 2*d in s:
        ans += 1
print(ans)
```
