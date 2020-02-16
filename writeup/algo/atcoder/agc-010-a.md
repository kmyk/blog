---
layout: post
alias: "/blog/2017/02/04/agc-010-a/"
date: "2017-02-04T23:05:32+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc010/tasks/agc010_a" ]
---

# AtCoder Grand Contest 010: A - Addition

## solution

偶奇 + コーナーケース。主に入力に$O(N)$。

数$A_i$はそれぞれ偶奇のみ見ればよい。
偶数はいくつあっても単一の偶数に潰せ、奇数はふたつで偶数ひとつになる。
よって奇数が奇数個ある場合が`NO`。ただし単一の奇数のみで偶数もない場合は`YES`。

## solution

``` python
#!/usr/bin/env python3
_ = int(input())
even = 0
odd = 0
for a in map(int, input().split()):
    if a % 2 == 0:
        even += 1
    else:
        odd += 1
ans = odd % 2 == 0 or (even == 0 and odd == 1)
print(['NO', 'YES'][ans])
```
