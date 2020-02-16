---
layout: post
alias: "/blog/2017/05/28/agc-015-a/"
date: "2017-05-28T03:30:05+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc015/tasks/agc015_a" ]
---

# AtCoder Grand Contest 015: A - A+...+B Problem

誤読の報告が多く見られた。分かる気もする。

## solution

$N$個の整数を昇順に並べてみれば、最大最小の制約から両端は固定、中央は$[A, B]$の範囲で自由。
よって$N = 1$や$A \gt B$でなければ$[B(N-2), A(N-2)]$の範囲で自由に作れる。
$O(1)$。

## implementation

``` python
#!/usr/bin/env python3
n, a, b = map(int, input().split())
if n <= 0 or a > b:
    ans = 0
elif n == 1:
    if a == b:
        ans = 1
    else:
        ans = 0
elif n >= 2:
    ans = b * (n-2) - a * (n-2) + 1
print(ans)
```
