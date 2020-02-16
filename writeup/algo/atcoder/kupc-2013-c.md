---
layout: post
alias: "/blog/2017/05/12/kupc-2013-c/"
date: "2017-05-12T20:28:49+09:00"
tags: [ "competitive", "writeup", "atcoder", "kupc" ]
"target_url": [ "https://beta.atcoder.jp/contests/kupc2013/tasks/kupc2013_c" ]
---

# 京都大学プログラミングコンテスト2013: C - チョコレート

$2$行目以降を反転させるところ、偶数行を反転と勘違いして$7$WA。submitによるdebugをした。

## solution

上から$1$行ずつ(独立に)食べていくとしてかまわない。各行について:

1.  右から左へ食べる
2.  左から右へ食べる
3.  両方から食べて合流する

のいずれか最も良いやつを選択。$2$行目以降はひとつ上の行により最初から反転している。$O(MN)$。

## implementation

``` python
#!/usr/bin/env python3
h, w = map(int, input().split())
result = 0
fnot = lambda a: 1 - a
for y in range(h):
    a = list(map(int, input().split()))
    if y != 0:
        a = list(map(fnot, a))
    l = a[0] + sum(map(fnot, a[1 :]))
    r = sum(map(fnot, a[: -1])) + a[-1]
    if w >= 3:
        b = a[0] + sum(map(fnot, a[1 : -1])) + (1 if 0 in map(fnot, a[1 : -1]) else -1) + a[-1]
    else:
        b = -1
    result += max([ l, r, b ])
print(result)
```
