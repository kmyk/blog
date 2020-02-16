---
layout: post
alias: "/blog/2017/09/04/arc-082-d/"
date: "2017-09-04T15:19:35+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "greedy" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc082/tasks/arc082_b" ]
---

# AtCoder Regular Contest 082: D - Derangement

## solution

なにか貪欲っぽく。$O(N)$。

$i$を$p\_i = i$なものの中で最小として$(i, i+1)$でswapすることを繰り返す。
$p\_i = i$であれば$p\_{i+1} \ne i$であるので、swapすれば$p\_i \ne i \land p\_{i+1} \ne i+1$となる。
これより早く解決する方法はないのは明らか(本当か？)なのでこれでよい。

## implementation

``` python
#!/usr/bin/env python3
n = int(input())
p = list(map(lambda p_i: int(p_i) - 1, input().split()))
result = 0
for i in range(n):
    if p[i] == i:
        j = i + 1
        if j >= n:
            j = i - 1
        p[i], p[j] = p[j], p[i]
        result += 1
print(result)
```
