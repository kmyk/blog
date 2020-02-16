---
layout: post
redirect_from:
  - /blog/2017/08/15/agc-006-b/
date: "2017-08-15T13:03:08+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc006/tasks/agc006_b" ]
---

# AtCoder Grand Contest 006: B - Median Pyramid Easy

## solution

同じ数字がふたつ並ぶともうそれは変化しない。
ピラミッドの中央に目標の$x$でそのようなものを作ればよい。
これは$x + 2, x - 1, x, x + 1, x - 2$などと並べればできる。$O(N)$。

## implementation

``` python
#!/usr/bin/env python3
n, x = map(int,input().split())
assert n >= 2
if x == 1 or x == 2 * n - 1:
    print('No')
else:
    a = [ x - 1, x, x + 1 ]
    b = list(range(1, x - 1)) + list(range(x + 2, 2 * n))
    c = b[n - 2 :] + a + b[: n - 2]
    print('Yes')
    print(*c, sep='\n')
```
