---
layout: post
alias: "/blog/2017/04/23/gcj-2017-round1a-a/"
date: "2017-04-23T01:08:35+09:00"
tags: [ "competitive", "writeup", "gcj" ]
"target_url": [ "https://code.google.com/codejam/contest/5304486/dashboard#s=p0" ]
---

# Google Code Jam 2017 Round 1A: A. Alphabet Cake

面白い問題。

## solution

横に伸ばしてから縦に伸ばす。$O(HW)$。

図から読みとってほしい:

```
????A??B?      AAAAAABBB      AAAAAABBB
?????????  ->  ?????????  ->  AAAAAABBB
???C???D?      CCCCDDDDD      CCCCDDDDD
?????????      ?????????      CCCCDDDDD
```

## implementation

``` python
#!/usr/bin/env python3
def solve(h, w, f):
    for y in range(h):
        c = None
        for x in range(w):
            if f[y][x] != '?':
                c = f[y][x]
                break
        if c is None:
            f[y] = None
            continue
        for x in range(w):
            if f[y][x] == '?':
                f[y][x] = c
            else:
                c = f[y][x]
    for y in range(h-1):
        if f[y+1] is None and f[y] is not None:
            f[y+1] = list(f[y])
    for y in reversed(range(h-1)):
        if f[y] is None and f[y+1] is not None:
            f[y] = list(f[y+1])
    return f
t = int(input())
for x in range(t):
    h, w = map(int, input().split())
    f = [ list(input()) for _ in range(h) ]
    print('Case #{}:\n{}'.format(x+1, '\n'.join(map(''.join, solve(h, w, f)))))
```
