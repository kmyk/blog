---
layout: post
alias: "/blog/2017/12/31/agc-004-a/"
title: "AtCoder Grand Contest 004: A - Divide a Cuboid"
date: "2017-12-31T18:39:59+09:00"
tags: [ "competitive", "writeup", "atcoder" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc004/tasks/agc004_a" ]
---

## solution

偶数長の辺があるならその辺で分ければちょうど半分。そうでないなら一番細いところで切る感じで。$O(1)$。

## implementation

``` python
#!/usr/bin/env python3
a, b, c = map(int, input().split())
if a % 2 == 0 or b % 2 == 0 or c % 2 == 0:
    result = 0
else:
    result = min(a * b, b * c, c * a)
print(result)
```
