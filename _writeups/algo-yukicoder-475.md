---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/475/
  - /blog/2017/01/16/yuki-475/
date: "2017-01-16T03:04:14+09:00"
tags: [ "competitive", "writeup", "yukicoder", "probability" ]
"target_url": [ "http://yukicoder.me/problems/no/475" ]
---

# Yukicoder No.475 最終日 - Writerの怠慢

## solution

順位を高い方からしゃくとりっぽく。$O(N)$。

順位$r$を取っても自分より得点が大きくならない参加者の数$f(r) = \|\{ i \ne \mathrm{writer_id} \| \land a_i + \mathrm{score}\_S(r) \le a\_{\mathrm{writer_id}} + \mathrm{score}\_S(1) \}\|$とする。
この関数$f$は広義単調増加である。よって$r$を増やしながら都度$f(r)$を更新すれば、$f$のグラフ$f \subset N \times N$は$O(N)$で求まる。

ある$1, 2, \dots, r-1$位まで決めてまだ自分より得点が大きい参加者がいないとき、まだ使われていない参加者は$n-r$人いて、そのうち$f(r)-r+1$人が$r$位を取ってもよい参加者。
確率にして$\frac{f(r)-r+1}{n-r}$。
これを掛け合わせればよい。優勝可能(つまり常に$f(r)-r+1 \ge 1$)とすると$\mathrm{ans} = \prod\_{1 \le r \le n-1} \frac{f(r)-r+1}{n-r}$。

## implementation

``` python
#!/usr/bin/env python3
n, s, writer_id = map(int, input().split())
a = list(map(int, input().split()))

score = lambda r: 50 * s + 250 * s // (4 + r)
self = a[writer_id] + score(1)
del a[writer_id]
a.sort()

p = 1.0
i = 0
for r in range(1, n):
    while i < len(a) and a[i] + score(r) <= self:
        i += 1
    p *= max(0, i-(r-1)) / (n-1 - (r-1))
print('%.12f' % p)
```
