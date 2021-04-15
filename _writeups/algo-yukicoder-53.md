---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/53/
  - /blog/2016/02/27/yuki-53/
date: 2016-02-27T08:46:36+09:00
tags: [ "competitive", "writeup", "yukicoder", "python", "rational", "math" ]
---

# Yukicoder No.53 悪の漸化式

埋め込みできるなあとか思いながら任意精度有理数で殴ってみたら通ってしまった。
`1.2828808741526015e-12`みたいな出力も許されるらしい。

## [No.53 悪の漸化式](http://yukicoder.me/problems/80)

``` python
#!/usr/bin/env python3
import fractions
n = int(input())
a = [None] * max(2, n + 1)
a[0] = fractions.Fraction(4)
a[1] = fractions.Fraction(3)
for i in range(2,len(a)):
    a[i] = (19 * a[i-1] -  12 * a[i-2]) / 4
print(float(a[n]))
```
