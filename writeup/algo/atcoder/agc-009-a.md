---
layout: post
alias: "/blog/2017/08/15/agc-009-a/"
date: "2017-08-15T15:58:59+09:00"
title: "AtCoder Grand Contest 009: A - Multiple Array"
tags: [ "competitive", "writeup", "atcoder", "agc", "greedy" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc009/tasks/agc009_a" ]
---

## solution

典型ぽい貪欲。最後の項を変えるには最後のボタンを押すしかないので、後ろから順にそのようにする。$O(N)$。

## implementation

必要になったから使ったのだけど`zip(*[ ... ])`は便利

``` python
#!/usr/bin/env python3
n = int(input())
a, b = zip(*[ map(int, input().split()) for _ in range(n) ])
c = 0
for i in reversed(range(n)):
    c += (- (a[i] + c)) % b[i]
print(c)
```
