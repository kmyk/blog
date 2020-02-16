---
layout: post
redirect_from:
  - /blog/2018/01/04/arc-088-c/
date: "2018-01-04T12:22:22+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "greedy" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc088/tasks/arc088_a" ]
---

# AtCoder Regular Contest 088: C - Multiple Gift

## solution

貪欲な感じ。列$A = (X, 2X, 4X, \dots, 2^{k-1}X)$で$Y \lt 2^kX$なものを作ればよい。$O(\log Y)$。

## implementation

``` python
#!/usr/bin/env python3
x, y = map(int, input().split())
cnt = 0
while x <= y:
    cnt += 1
    x *= 2
print(cnt)
```
