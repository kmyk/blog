---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/381/
  - /blog/2016/06/22/yuki-381/
date: 2016-06-22T04:06:12+09:00
tags: [ "competitive", "writeup", "yukicoder" ]
---

# Yukicoder No.381 名声値を稼ごう Extra

-   <http://yukicoder.me/problems/no/381>
-   [No.378 名声値を稼ごう](http://yukicoder.me/problems/922)の制約強化版

## solution

単純には、$2N - (N + \lfloor \frac{N}{2} \rfloor + \dots + 0)$が答え。
これらを$2$進数で書くと、単に`popcount`すればよいことに気付ける。
$N$は$2^k$の整数に分解してそれぞれ考えて構わないことを見ると理解しやすい。

## implementation

``` python
#!/usr/bin/env python3
print(bin(int(input())).count('1'))
```
