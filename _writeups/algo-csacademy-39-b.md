---
layout: post
redirect_from:
  - /writeup/algo/csacademy/39-b/
  - /writeup/algo/cs-academy/39-b/
  - /blog/2017/07/27/csa-39-b/
date: "2017-07-27T03:03:12+09:00"
tags: [ "competitive", "writeup", "csacademy" ]
"target_url": [ "https://csacademy.com/contest/round-39/task/circle-elimination/" ]
---

# CS Academy Round #39: B. Circle Elimination

これは問題文が楽。

## solution

配列$a$は添字 $\mapsto$ 値の関数として見れるが(値, 添字)の対の列として見て整列すれば、順に舐めて隣接項間の距離の総和が答え。$O(N \log N)$。

## implementation

``` python
#!/usr/bin/env python3
import random
n = int(input())
a = list(map(int, input().split()))
b = [ None ] * n
for i, a_i in enumerate(a):
    b[i] = ( a_i, i )
b.sort()
result = 0
for i in range(n - 1):
    k = abs(b[i + 1][1] - b[i][1])
    result += min(k, n - k)
print(result)
```
