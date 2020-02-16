---
layout: post
alias: "/blog/2017/01/07/abc-051-b/"
date: "2017-01-07T22:12:32+09:00"
tags: [ "competitive", "writeup", "atcoder", "abc" ]
"target_url": [ "https://beta.atcoder.jp/contests/abc051/tasks/abc051_b" ]
---

# AtCoder Beginner Contest 051: B - Sum of Three Integers

## solution

等式$X + Y + Z = K$を満たす必要があるので、自由度は$2$。$O(K^2)$。

## implementation

``` python
#!/usr/bin/env python3
k, s = map(int, input().split())
ans = 0
for x in range(k+1):
    for y in range(x, k+1):
        z = s - x - y
        if x <= y <= z <= k:
            ans += [ None, 1, 3, 6 ][ len(set([ x, y, z ])) ]
print(ans)
```
