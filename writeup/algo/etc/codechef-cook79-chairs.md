---
layout: post
alias: "/blog/2018/04/05/codechef-cook79-chairs/"
title: "CodeChef Cook79: B. Chairs"
date: "2018-04-05T06:48:39+09:00"
tags: [ "competitive", "writeup", "codechef" ]
"target_url": [ "https://www.codechef.com/COOK79/problems/CHAIRS" ]
---

## solution

`0`の数 - 最長の連続する`0`の長さ が答え。

## implementation

``` python
#!/usr/bin/env python3
t = int(input())
for _ in range(t):
    n = int(input())
    s = input()
    s.split('1')
    i = s.find('1')
    s = s[i :] + s[: i]
    zeros = s.split('1')
    result = sum(map(len, zeros)) - max(map(len, zeros))
    print(result)
```
