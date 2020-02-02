---
layout: post
alias: "/blog/2018/01/01/code-festival-2017-qualc-b/"
title: "CODE FESTIVAL 2017 qual C: B - Similar Arrays"
date: "2018-01-01T12:14:02+09:00"
tags: [ "competitive", "writeup", "codefestival" ]
"target_url": [ "https://beta.atcoder.jp/contests/code-festival-2017-qualc/tasks/code_festival_2017_qualc_b" ]
---

## solution

項ごとに独立。
$A\_i$が偶数なら$b\_i = A\_i$のひとつ、奇数なら$b\_i = A\_i \pm 1$のふたつの選択肢がある。
そのようにして掛け合わせればよい。$O(N)$。

## implementation

``` python
#!/usr/bin/env python3
n = int(input())
a = list(map(int, input().split()))
k = 1
for a_i in a:
    if a_i % 2 == 0:
        k *= 2
print(3 ** n - k)
```
