---
layout: post
redirect_from:
  - /writeup/algo/atcoder/agc-007-a/
  - /blog/2017/08/10/agc-007-a/
date: "2017-08-10T17:05:12+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc007/tasks/agc007_a" ]
---

# AtCoder Grand Contest 007: A - Shik and Stone

$1$WA。

## solution

`#`の数が$H + W - 1$に一致するか見る。$O(HW)$。

## implementation

``` python
#!/usr/bin/env python3
def solve(h, w, a):
    b = []
    b += [ '.' * (w + 2) ]
    b += [ '.' + row + '.' for row in a ]
    b += [ '.' * (w + 2) ]
    y, x = 1, 1
    while (y, x) != (h, w):
        if b[y - 1][x] == b[y][x - 1] == '#':
            return False
        if b[y + 1][x] == b[y][x + 1] == '#':
            return False
        if b[y + 1][x] == '#':
            y += 1
        elif b[y][x + 1] == '#':
            x += 1
        else:
            return False
    return True
h, w = map(int, input().split())
a = [ input() for _ in range(h) ]
print(['Impossible', 'Possible'][solve(h, w, a)])
```
