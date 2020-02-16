---
layout: post
alias: "/blog/2017/12/31/arc-080-c/"
date: "2017-12-31T20:31:41+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc080/tasks/arc080_a" ]
---

# AtCoder Regular Contest 080: C - 4-adjacent

## solution

素因数中の$2$の数にだけ注目する。`14141414141222222`のような並びを作れるか判定すればよい。$O(N)$。

## implementation

``` python
#!/usr/bin/env python3
n = int(input())
a = list(map(int, input().split()))
k1, k2, k4 = 0, 0, 0
for a_i in a:
    if a_i % 4 == 0:
        k4 += 1
    elif a_i % 2 == 0:
        k2 += 1
    else:
        k1 += 1
t = min(k1, k4)
k1 -= t
k4 -= t
result = k1 == 0 or (k1 == 1 and not k2)
print([ 'No', 'Yes' ][result])
```
