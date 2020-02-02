---
layout: post
alias: "/blog/2018/01/01/arc-057-c/"
title: "AtCoder Regular Contest 057: C - 2乗根"
date: "2018-01-01T22:28:39+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "multiprecision" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc057/tasks/arc057_c" ]
---

## solution

$10$進数展開$a\_1 a\_2 \dots a\_k$として与えられる整数を$A$とおく。求める整数$N = \min \\{ n \mid \exists k. A \le \sqrt{n} \times 10^k \lt A + 1 \\}$。
$A \le \sqrt{N} \times 10^k \lt A + 1$と$A^2 \le N \times 10^{2k} \lt (A + 1)^2$は同値なので、$A^2$を計算しこれをもとに$N$を探す。
$N$は$A^2$の下$2k$桁を切り上げて潰したものであるので$N = \lceil \frac{A^2}{10^{2k}} \rceil$。$k$を増やしながら見ていけばよい。
計算量は多倍長整数の実装に強く依るが、内部で$10$進法を意識して保持してやれば$O(k^2)$にできるだろう。

## implementation

``` python
#!/usr/bin/env python3
a = int(input())
l = a ** 2
r = (a + 1) ** 2
e = 1
while (l + e - 1) // e * e < r:
    n = (l + e - 1) // e
    e *= 100
print(n)
```
