---
layout: post
alias: "/blog/2017/03/07/yahoo-procon-2017-qual-b/"
date: "2017-03-07T17:21:07+09:00"
tags: [ "competitive", "writeup", "atcoder", "yahoo-procon", "greedy" ]
"target_url": [ "https://beta.atcoder.jp/contests/yahoo-procon2017-qual/tasks/yahoo_procon2017_qual_b" ]
---

# 「みんなのプロコン」: B - オークション

## solution

開始時点での値段でsortして安いのから順に$K$個買う。買う順序は重要でないが、安い方から取ればよい。$O(N \log N)$。

## implementation

``` python
#!/usr/bin/env python3
n, k = map(int, input().split())
a = sorted(map(int, input().split()))
acc = 0
for i in range(k):
    acc += a[i] + i
print(acc)
```
