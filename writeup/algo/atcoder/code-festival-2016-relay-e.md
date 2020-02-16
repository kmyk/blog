---
layout: post
redirect_from:
  - /blog/2016/11/30/code-festival-2016-relay-e/
date: "2016-11-30T01:33:24+09:00"
tags: [ "competitive", "writeup", "atcoder", "codefestival" ]
"target_url": [ "https://beta.atcoder.jp/contests/cf16-relay-open/tasks/relay_e" ]
---

# CODE FESTIVAL 2016 Relay: E - 方眼紙と線分 / Segment on Grid Paper

本番、配られたゼッケン代わりのシールの台紙を方眼紙として利用していた。

## solution

$H = \|A - C\|, \; W = \|B - D\|$として左下を原点にし右上に進むようにしてよい。
$H_1 = H \cdot \frac{1}{\mathrm{gcd}(H, W)}, \; W_1 = W \cdot \frac{1}{\mathrm{gcd}(H, W)}$とすると、線分が格子点上を通るのはその端点のみとなる。このとき横切るマスの数は$H_1 + W_1 - 1$となり、これを$\mathrm{gcd}(H, W)$倍すれば答え。

## implementation

atcoderは`Python3 (3.4.3)`だから`math.gcd`がないあれを踏んでREした。

``` python
#!/usr/bin/env python3
import fractions
a, b, c, d = map(int, input().split())
h = abs(a - c)
w = abs(b - d)
if h == 0 or w == 0:
    ans = 0
else:
    h1 = h // fractions.gcd(h, w)
    w1 = w // fractions.gcd(h, w)
    ans = (h1 + w1 - 1) * fractions.gcd(h, w)
print(ans)
```
