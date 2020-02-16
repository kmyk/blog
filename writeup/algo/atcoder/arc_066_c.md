---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc-066-c/
  - /blog/2018/04/05/arc-066-c/
date: "2018-04-05T01:23:47+09:00"
tags: [ "competitive", "writeup", "arc" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc066/tasks/arc066_a" ]
---

# AtCoder Regular Contest 066: C - Lining Up

## solution

問題文を読むと「「自分の左に並んでいた人数と自分の右に並んでいた人数の差の絶対値」なんてこんなん絶対左右対象やろ$2^{\lfloor \frac{N}{2} \rfloor}$が答え」みたいな気分になるので、そんな感じにしてサンプルが合うまでがちゃがちゃやると解ける。$O(N)$。

## implementation

``` python
#!/usr/bin/env python3
n = int(input())
a = list(map(int, input().split()))
a.sort()
try:
    for i, a_i in enumerate(a):
        if n % 2 == 1:
            assert a_i == (i + 1) // 2 * 2
        else:
            assert a_i == i // 2 * 2 + 1
    answer = pow(2, n // 2, 10 ** 9 + 7)
except AssertionError:
    answer = 0
print(answer)
```
