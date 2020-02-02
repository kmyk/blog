---
layout: post
alias: "/blog/2018/01/23/arc-089-c/"
title: "AtCoder Regular Contest 089: C - Traveling"
date: "2018-01-23T19:41:41+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc089/tasks/arc089_a" ]
---

## solution

時刻$0, t\_1, t\_2, \dots, t\_N$での位置は決まっているので、それらの間の移動ごとに分けて考えてよい。この移動可能性は到達してからその近くで足踏みすると見れば$O(1)$で求まる。全体で$O(N)$。

## implementation

``` python
#!/usr/bin/env python3
def pred(t, x, y):
    return x + y <= t and (x + y - t) % 2 == 0
result = True
t, x, y = 0, 0, 0
for _ in range(int(input())):
    nt, nx, ny = map(int, input().split())
    if not pred(nt - t, abs(nx - x), abs(ny - y)):
        result = False
        break
    t, x, y = nt, nx, ny
print(['No', 'Yes'][result])
```
