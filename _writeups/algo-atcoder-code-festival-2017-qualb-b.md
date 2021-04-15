---
layout: post
redirect_from:
  - /writeup/algo/atcoder/code-festival-2017-qualb-b/
  - /blog/2017/11/10/code-festival-2017-qualb-b/
date: "2017-11-10T23:55:43+09:00"
tags: [ "competitive", "writeup", "atcoder", "codefestival" ]
"target_url": [ "https://beta.atcoder.jp/contests/code-festival-2017-qualb/tasks/code_festival_2017_qualb_b" ]
---

# CODE FESTIVAL 2017 qual B: B - Problem Set

## solution

多重集合として$T \subseteq D$か見ればよい。sortして一緒に先頭から削っていく。$O(N \log N)$。

## implementation

``` python
#!/usr/bin/env python3
n = int(input())
d = list(map(int, input().split()))
m = int(input())
t = list(map(int, input().split()))
d.sort()
t.sort()
j = 0
for t_i in t:
    while j < n and d[j] < t_i:
        j += 1
    if j == n or d[j] != t_i:
        result = False
        break
    j += 1
else:
    result = True
print(['NO', 'YES'][result])
```
