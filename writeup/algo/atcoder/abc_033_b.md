---
layout: post
redirect_from:
  - /writeup/algo/atcoder/abc-033-b/
  - /blog/2016/02/06/abc-033-b/
date: 2016-02-06T23:22:49+09:00
tags: [ "competitive", "writeup", "atcoder", "abc" ]
---

# AtCoder Beginner Contest 033 B - 町の合併

辞書っぽい構造や$10^9$程度の大きさの数値演算というbrainfuckでやるには面倒な要素が詰まっている問題。しかし割り算はないので頑張ればできるだろう。

## [B - 町の合併](https://beta.atcoder.jp/contests/abc033/tasks/abc033_b)

``` python
#!/usr/bin/env python3
n = int(input())
max_s, max_p = None, -1
acc = 0
for i in range(n):
    s, p = input().split()
    p = int(p)
    if max_p < p:
        max_s, max_p = s, p
    acc += p
if acc < 2*max_p:
    print(max_s)
else:
    print('atcoder')
```
