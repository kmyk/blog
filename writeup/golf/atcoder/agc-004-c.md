---
layout: post
alias: "/blog/2017/08/07/agc-004-c/"
title: "AtCoder Grand Contest 004: C - AND Grid"
date: "2017-08-07T15:29:09+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc", "golf", "sed" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc004/tasks/agc004_c" ]
---

後輩に「おすすめの問題ない？」って聞いたら返ってきた問題。たしかに面白い問題。

プロがsedでgolfしていたから追ってsed golfした。$5$byte届かず。

## implementation

### bash

空白詰めると$57$byte。

``` sh
#!/bin/bash
s='
    ~2s/./#/2g
    s/.$/#/
    1x
'
tee f | rev | sed 1$s | rev
sed 2$s f
```

### python

``` python
#!/usr/bin/env python3
import copy
h, w = map(int, input().split())
f = [ list(input()) for _ in range(h) ]
a = copy.deepcopy(f)
b = copy.deepcopy(f)
a[0] = '#' * w
for y in range(1, h - 1):
    for x in range(w):
        [a, b][x % 2][y][x] = '#'
b[h - 1] = '#' * w
print(*map(''.join, a), sep='\n')
print()
print(*map(''.join, b), sep='\n')
```
