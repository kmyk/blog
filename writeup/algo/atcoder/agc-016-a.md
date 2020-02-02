---
layout: post
alias: "/blog/2017/08/09/agc-016-a/"
date: "2017-08-09T21:46:12+09:00"
title: "AtCoder Grand Contest 016: A - Shrinking"
tags: [ "competitive", "writeup", "atcoder", "agc" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc016/tasks/agc016_a" ]
---

## solution

最終的に残る文字種を総当たり。
文字種$L = 26$が掛かって$O(L\|s\|^2)$。

## implementation

``` c++
#!/usr/bin/env python3
import string
s = input()
result = float('inf')
for last in string.ascii_lowercase:
    t = list(s)
    while not all(c == last for c in t):
        for i in range(len(t)):
            if last in t[i : i + 2]:
                t[i] = last
        t.pop()
    result = min(result, len(s) - len(t))
print(result)
```
