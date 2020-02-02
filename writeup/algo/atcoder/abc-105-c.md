---
layout: post
title: "AtCoder Beginner Contest 105: C - Base -2 Number"
date: 2018-08-11T23:06:13+09:00
tags: [ "competitive", "writeup", "atcoder", "abc" ]
"target_url": [ "https://beta.atcoder.jp/contests/abc105/tasks/abc105_c" ]
---

## solution

制約緩和。
ひとまず $S_i^+, S_i^- \ge 0$ を使って $n = S_0^+ \cdot 2^0 + S_0^- \cdot (-2)^0 + S_1^+ \cdot 2^1 + S_1^- \cdot (-2)^1 + S_2^+ \cdot 2^2 + S_2^- \cdot (-2)^2 + \dots$ と書く。これを相互に繰り上げる形で整理していく。$O(\log N)$。

## note

$30$分かかった。
bitをにらんでえいってやろうとしてたのが間違い。
すぐに思い付けるとはいえ「頭いいなあ」に分類される種類の解法に見える。

半分全列挙という単語が流れてきたのでできるのかも。

## implementation

``` python
#!/usr/bin/env python3
n = int(input())

pos = [ 0 ] * 64
neg = [ 0 ] * 64
for i in range(32):
    if n >= 0:
        if n & (1 << i):
            pos[i] += 1
    else:
        if (- n) & (1 << i):
            neg[i] += 1

for i in range(32):
    delta = min(pos[i], neg[i])
    pos[i] -= delta
    neg[i] -= delta
    if i % 2 == 1:
        if pos[i]:
            pos[i + 1] += pos[i]
            neg[i] += pos[i]
            pos[i] = 0
        neg[i + 1] += neg[i] // 2
        neg[i] %= 2
    else:
        if neg[i]:
            neg[i + 1] += neg[i]
            pos[i] += neg[i]
            neg[i] = 0
        pos[i + 1] += pos[i] // 2
        pos[i] %= 2

s = ''
for i in reversed(range(64)):
    if pos[i] or neg[i]:
        s += '1'
    else:
        s += '0'
print(s.lstrip('0') or '0')
```
