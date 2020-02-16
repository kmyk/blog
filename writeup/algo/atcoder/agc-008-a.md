---
layout: post
redirect_from:
  - /blog/2016/12/25/agc-008-a/
date: "2016-12-25T23:01:20+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc008/tasks/agc008_a" ]
---

# AtCoder Grand Contest 008: A - Simple Calculator

これはすぐだった。

## solution

反転をするのは最初か最後だけでよい。$O(1)$。

## implementation

``` python
#!/usr/bin/env python3
x, y = map(int, input().split())
ans = float('inf')
f = lambda z: [ z, float('inf') ][ z < 0 ]
ans = min(ans, f(   y  -    x )    )
ans = min(ans, f(   y  - (- x)) + 1)
ans = min(ans, f((- y) -    x ) + 1)
ans = min(ans, f((- y) - (- x)) + 2)
print(ans)
```
