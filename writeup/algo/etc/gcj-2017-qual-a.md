---
layout: post
redirect_from:
  - /blog/2017/04/10/gcj-2017-qual-a/
date: "2017-04-10T02:45:05+09:00"
tags: [ "competitive", "writeup", "gcj", "greedy" ]
"target_url": [ "https://code.google.com/codejam/contest/3264486/dashboard#s=p0" ]
---

# Google Code Jam Qualification Round 2017: A. Oversized Pancake Flipper

## solution

$1$次元LigthsOut。貪欲。$O(N^2)$。imos法とかすれば$O(N)$になるはず。

## implementation

``` python
#!/usr/bin/env python3
def solve(s, k):
    s = list(map(lambda c: int(c == '+'), s))
    cnt = 0
    for i, c in enumerate(s):
        if not c and i + k <= len(s):
            cnt += 1
            for di in range(k):
                s[i+di] ^= 1
    if 0 in s:
        return 'IMPOSSIBLE'
    else:
        return cnt
t = int(input())
for x in range(t):
    s, k = input().split()
    k = int(k)
    print('Case #{}: {}'.format(x+1, solve(s, k)))
```
