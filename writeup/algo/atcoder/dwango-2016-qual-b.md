---
layout: post
redirect_from:
  - /writeup/algo/atcoder/dwango-2016-qual-b/
  - /blog/2016/01/23/dwango-2016-qual-b/
date: 2016-01-23T22:12:13+09:00
tags: [ "competitive", "writeup", "atcoder", "dwango" ]
---

# 第2回 ドワンゴからの挑戦状 予選 B - 積み鉛筆

直感を信じて投げてみたら通った。

## [B - 積み鉛筆](https://beta.atcoder.jp/contests/dwango2016-prelims/tasks/dwango2016qual_b)

### 解説

$k_i, k\_{i+1}$から$l\_{i+1}$を決めたい。
条件より$k_i = {\rm max} \\{ l_i, l\_{i+1} \\}$であるが、$k_i \lt l\_{i+1}$であればこれに矛盾する。
同様に$k\_{i+1} = {\rm max} \\{ l\_{i+1}, l\_{i+2} \\}$であるが、$k\_{i+1} \lt l\_{i+1}$であれば矛盾。
つまり$l\_{i+1} \le {\rm min} \\{ k_i, k\_{i+1} \\}$である。

ここから$l\_{i+1} = {\rm min} \\{ k_i, k\_{i+1} \\}$としてよいことは明らかであり、これが答え。両端は適当に。

### 実装

``` python
#!/usr/bin/env python3
n = int(input())
k = list(map(int,input().split()))
l = []
l.append(k[0])
for i in range(len(k)-1):
    l.append(min(k[i], k[i+1]))
l.append(k[-1])
print(*l)
```
