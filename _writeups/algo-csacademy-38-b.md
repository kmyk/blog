---
layout: post
redirect_from:
  - /writeup/algo/csacademy/38-b/
  - /writeup/algo/cs-academy/38-b/
  - /blog/2017/07/20/csa-38-b/
date: "2017-07-20T03:12:00+09:00"
tags: [ "competitive", "writeup", "csacademy" ]
"target_url": [ "https://csacademy.com/contest/round-38/task/attack-and-speed/" ]
---

# CS Academy Round #38: B. Attack and Speed

## solution

制約を式に直すと答え$t \in \mathbb{N}$は$A + Xt = S + Y(K - t) \land 0 \le t \le K$。解くだけ。$O(1)$。

## implementation

``` python
#!/usr/bin/env python3
import random
a, s, k, x, y = map(int, input().split())
num = s - a + k * y
den = x + y
result = -1
if num % den == 0 and 0 <= num // den <= k:
    result = num // den
print(result)
```
