---
layout: post
alias: "/blog/2016/12/20/world-codesprint-8-climbing-the-leaderboard/"
date: "2016-12-20T02:33:02+09:00"
tags: [ "competitive", "writeup", "hackerrank", "world-codesprint" ]
"target_url": [ "https://www.hackerrank.com/contests/world-codesprint-8/challenges/climbing-the-leaderboard" ]
---

# HackerRank World CodeSprint 8: Climbing the Leaderboard

## solution

Emulate it with $2$ indices $0 \le i \lt n$ and $0 \le i \lt m$. $O(n + m)$.

## implementation

``` python
#!/usr/bin/env python3
_ = int(input())
scores = sorted(set(map(int, input().split())))
_ = int(input())
alice = list(map(int, input().split()))
i = 0
for s in alice:
    while i < len(scores) and scores[i] <= s:
        i += 1
    print(len(scores)-i+1)
```
