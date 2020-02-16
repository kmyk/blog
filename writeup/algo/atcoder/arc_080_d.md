---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc-080-d/
  - /blog/2017/12/31/arc-080-d/
date: "2017-12-31T20:33:59+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc080/tasks/arc080_b" ]
---

# AtCoder Regular Contest 080: D - Grid Coloring

## solution

ヘビ。$O(HW)$。[平面上のロシアゲー（構築ゲー）を解くためのそこそこ一般的なテクについて - Learning Algorithms](http://kokiymgch.hatenablog.com/entry/2017/12/12/153419)。

## implementation

``` python
#!/usr/bin/env python3
h, w = map(int, input().split())
n = int(input())
a = list(map(int, input().split()))
i = 0
for y in range(h):
    row = []
    for _ in range(w):
        row += [ i + 1 ]
        a[i] -= 1
        if a[i] == 0:
            i += 1
    if y % 2 == 1:
        row = reversed(row)
    print(*row)
```
