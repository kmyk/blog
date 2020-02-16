---
layout: post
date: 2018-07-01T23:11+09:00
tags: [ "atcoder", "arc", "competitive", "writeup" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc100/tasks/arc100_a" ]
redirect_from:
  - /writeup/algo/atcoder/arc-100-c/
---

# AtCoder Regular Contest 100: C - Linear Approximation

## solution

<span>$a_i \gets a_i - i$</span>と取り直し(典型 1)てその中央値(典型 2)が$b$。
中央値でいいことの証明は$\pm 1$してみたときの差を考えればすぐで、ここから$N$が偶数のときに雑にやってよいことも言える。
$O(N \log N)$。

## implementation

``` python
#!/usr/bin/env python3
n = int(input())
a = list(map(int, input().split()))
for i in range(n):
    a[i] -= i
a.sort()
b = a[n // 2]
answer = 0
for a_i in a:
    answer += abs(a_i - b)
print(answer)
```
