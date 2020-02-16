---
layout: post
redirect_from:
  - /blog/2016/07/13/code-festival-2015-okinawa-open-a/
date: "2016-07-13T02:52:39+09:00"
tags: [ "competitive", "writeup", "codefestival", "atcoder", "construction" ]
"target_url": [ "https://beta.atcoder.jp/contests/code-festival-2015-okinawa-open/tasks/code_festival_2015_okinawa_a" ]
---

# CODE FESTIVAL 2015 OKINAWA OPEN A - Automatic Map Generator

構成をするだけ。
左上から順に$1 \times 1$の島を植えていく。

``` python
#!/usr/bin/env python3
h, w, k = map(int,input().split())
f = [['.' for x in range(w)] for y in range(h)]
for y in range(0, h, 2):
    for x in range(0, w, 2):
        if k:
            f[y][x] = '#'
            k -= 1
if k:
    print('IMPOSSIBLE')
else:
    for line in f:
        print(*line, sep='')
```
