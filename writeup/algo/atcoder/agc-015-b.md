---
layout: post
alias: "/blog/2017/05/28/agc-015-b/"
date: "2017-05-28T03:30:07+09:00"
title: "AtCoder Grand Contest 015: B - Evilator"
tags: [ "competitive", "writeup", "atcoder", "agc" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc015/tasks/agc015_b" ]
---

## solution

最小化するのは距離でなく乗る回数なので、どこからどこへ行くにも$1$階あるいは$N$階まで行ってしまえば$2$回乗るので十分。
$i \ne j$として$i \to j$が$1$回乗るので済むのは次と同値: $S\_i$が`U`かつ$i \lt j$あるいは$S\_j$が`D`かつ$j \lt i$。
そのようなものを数えればよいが、$i$を固定すればそのような$j$の数は$O(1)$。よって全体で$O(N)$。

## problem

``` python
#!/usr/bin/env python3
s = input()
n = len(s)
ans = n**2 * 2
for i, c in enumerate(s):
    if c == 'U':
        ans -= (n-i-1)
    elif c == 'D':
        ans -= i
    ans -= 2
print(ans)
```
