---
layout: post
alias: "/blog/2016/10/31/agc-006-a/"
date: "2016-10-31T15:36:42+09:00"
title: "AtCoder Grand Contest 006: A - Prefix and Suffix"
tags: [ "competitive", "writeup", "atcoder", "agc", "golf" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc006/tasks/agc006_a" ]
---

``` python
#!/usr/bin/env python3
import itertools
n = int(input())
s = input()
t = input()
for l in itertools.count(n):
    it = (s + 'a' * l)[: l - len(t)] + t
    if len(it) >= n and it.startswith(s) and it.endswith(t):
        break
print(len(it))
```

## golf 鑑賞

%20さんのperl解: <https://beta.atcoder.jp/contests/agc006/submissions/958849>

まず$\|s\| = \|t\| = N$なので$1$行目$N$は捨ててよい。
残りの$2$行の全体に対し、改行を中心として`s/(.*)\n\1/$1/`として置換することで重複部分(で最大のもの)を消去できる。
末尾の改行を削ったものの長さが答え。
`` `dd` ``は`` `cat` ``で置き換えても動く。
正規表現の`r` optionはnon-destructive modifierらしい。
