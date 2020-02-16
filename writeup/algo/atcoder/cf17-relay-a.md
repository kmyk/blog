---
layout: post
alias: "/blog/2017/11/27/cf17-relay-a/"
date: "2017-11-27T17:58:05+09:00"
tags: [ "competitive", "writeup", "atcoder", "codefestival", "team-relay" ]
"target_url": [ "https://beta.atcoder.jp/contests/cf17-relay-open/tasks/relay2_a" ]
---

# Code Festival Team Relay: A - Kaiden

## solution

$O(1)$。

$a - b \le 0 \land a \lt k$のときが$-1$なのはそうとして、それ以外で$a - b = 0$のときに零除算しないよう注意。

## implementation

``` python
#!/usr/bin/env python3
def solve(k, a, b):
    if a - b <= 0:
        if k <= a:
            return 1
        else:
            return -1
    return 1 + (k - a + (a - b) - 1) // (a - b) * 2
k, a, b = map(int, input().split())
print(solve(k, a, b))
```
