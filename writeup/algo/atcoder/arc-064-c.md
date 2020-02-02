---
layout: post
alias: "/blog/2016/12/05/arc-064-c/"
date: "2016-12-05T15:43:04+09:00"
title: "AtCoder Regular Contest 064: C - Boxes and Candies"
tags: [ "competitive", "writeup", "atcoder", "greedy" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc064/tasks/arc064_a" ]
---

## solution

貪欲。$O(N)$。

$i$番目まで条件を満たしていて$a_i + a\_{i+1} \ge x$とする。
$a_i$と$a\_{i+1}$のどちらかを減らすのだが、$a_i$を減らすことに意味はないため$a\_{i+1}$を減らせばよい。
$a\_{i+1} \ge 0$の制約があることに注意。

## implementation

``` python
#!/usr/bin/env python3
n, x = map(int, input().split())
a = list(map(int, input().split()))
ans = 0
for i in range(n-1):
    delta = max(0, a[i] + a[i+1] - x)
    a[i+1] -= delta
    if a[i+1] < 0:
        a[i] += a[i+1]
        a[i+1] = 0
    ans += delta
print(ans)
```
