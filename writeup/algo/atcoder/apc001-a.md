---
layout: post
date: 2018-07-09T20:26:40+09:00
tags: [ "competitive", "writeup", "atcoder", "apc" ]
"target_url": [ "https://beta.atcoder.jp/contests/apc001/tasks/apc001_a" ]
---

# AtCoder Petrozavodsk Contest 001: A - Two Integers

## note

そこそこ大きい$k$まで$kx$を試せばきっと十分でしょと試してACでしたが、実質的なWAだったので反省しています。

## implementation

``` python
#!/usr/bin/env python3
x, y = map(int, input().split())
for k in range(1, 100000):
    if k * x % y != 0:
        print(k * x)
        break
else:
    print(-1)
```
