---
layout: post
alias: "/blog/2017/08/27/agc-019-a/"
date: "2017-08-27T00:14:19+09:00"
title: "AtCoder Grand Contest 019: A - Ice Tea Store"
tags: [ "competitive", "writeup", "atcoder", "agc", "dp" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc019/tasks/agc019_a" ]
---

## solution

$H \gets \max \\{ H, 2Q \\}$などとすれば$D$以外を忘れてよい。
$N \equiv 1 \pmod{2}$のときだけは$S$を使う。$O(1)$。

## implementation

``` python
#!/usr/bin/env python3
q, h, s, d = map(int, input().split())
n = int(input())
h = min(h, q + q)
s = min(s, h + h)
d = min(d, s + s)
print((n // 2) * d + (n % 2) * s)
```
