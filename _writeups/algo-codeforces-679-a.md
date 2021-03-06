---
layout: post
redirect_from:
  - /writeup/algo/codeforces/679-a/
  - /blog/2016/06/09/cf-679-a/
date: 2016-06-09T05:25:16+09:00
tags: [ "competitive", "writeup", "codeforces", "reactive" ]
"target_url": [ "http://codeforces.com/contest/679/problem/A" ]
---

# Codeforces Round #356 (Div. 1) A. Bear and Prime 100

This seems the first reactive problem in regular round of codeforces.
So, [Interactive Problems: Guide for Participants](http://codeforces.com/blog/entry/45307) was shown in the site header.

ところで`Idleness Limit Exceeded`はとても親切なのでyukicoderやatcoderにも実装されるべき。

## problem

ある数が隠されている。以下の質問を$20$回以下用いて、それが素数であるかどうかを判定せよ。

-   $[2,100]$の範囲の自然数に関して、それが目標の数の約数であるかどうか

## solution

Check only the pairs of primes $(p, q)$, where $pq \le 100$.
So you should ask for each $2,3,5,7,11,13,17,\dots,47$, and $2^2, 3^2, 5^2, 7^2$ if necessary.

## implementation

-   don't forget `flush`
-   don't ask too large number like $11^2 = 121$

``` python
#!/usr/bin/env python3
import sys
def query(n):
    print(n)
    sys.stdout.flush()
    return input() == 'yes'
primes = [ 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97 ]
divisors = []
i = 0
k = 1
for _ in range(18):
    n = pow(primes[i], k)
    if n <= 100 and query(n):
        divisors.append(n)
        k += 1
    else:
        k = 1
        i += 1
print('prime' if len(divisors) <= 1 else 'composite')
```
