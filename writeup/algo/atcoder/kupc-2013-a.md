---
layout: post
alias: "/blog/2017/05/12/kupc-2013-a/"
date: "2017-05-12T20:28:46+09:00"
title: "京都大学プログラミングコンテスト2013: A - 旧総合研究７号館"
tags: [ "competitive", "writeup", "atcoder", "kupc" ]
"target_url": [ "https://beta.atcoder.jp/contests/kupc2013/tasks/kupc2013_a" ]
---

## implementation

雑に書いてWAした。loopを抜けた後にも確認と出力が必要な形で書いたのにそれを忘れた。

``` python
#!/usr/bin/env python3
n, q = map(int, input().split())
xs = []
xs += [( 0, 'kogakubu10gokan' )]
for _ in range(n):
    year, name = input().split()
    xs += [( int(year), name )]
while True:
    year, name = xs.pop()
    if year <= q:
        print(name)
        break
```
