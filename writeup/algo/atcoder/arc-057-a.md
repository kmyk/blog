---
layout: post
redirect_from:
  - /blog/2016/07/10/arc-057-a/
date: "2016-07-10T15:36:21+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc057/tasks/arc057_a" ]
---

# AtCoder Regular Contest 057 A - 2兆円

$2$兆円ほしい

## solution

$K = 0$の自明な場合を除いて、素直に計算すれば間に合う。$O(\log A)$。

漸化式は$t \gets t + (1 + Kt)$であり、$t \gets (1 + K)t + 1$と直せる。$1 + K \ge 2$のときこれは指数的に増加し、愚直に計算して間に合う。
$1 + K = 1$のときは$1$回の操作でちょうど$1$のみ増加するので、愚直にやると間に合わないが、明らかな$O(1)$で求まる。

## implementation

``` python
#!/usr/bin/env python3
l = 2*10**12
a, k = map(int,input().split())
if k == 0:
    i = l - a
else:
    i = 0
    while a < l:
        a += 1 + k*a
        i += 1
print(i)
```
