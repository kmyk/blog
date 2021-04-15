---
layout: post
redirect_from:
  - /writeup/algo/csacademy/39-c/
  - /writeup/algo/cs-academy/39-c/
  - /blog/2017/07/27/csa-39-c/
date: "2017-07-27T03:03:13+09:00"
tags: [ "competitive", "writeup", "csacademy" ]
"target_url": [ "https://csacademy.com/contest/round-39/task/reconstruct-sum/" ]
---

# CS Academy Round #39: C. Reconstruct Sum

入力の与えられる向きに関する英語が難しい。

## solution

繰り上がりの状況は固定されているので各桁は完全に独立。
それぞれ個数を数え足し合わせる。
$O(\log S)$。

## implementation

``` python
#!/usr/bin/env python3
s = int(input())
log_s = len(str(s))
is_carried = list(map(int, input().split())) + [ 0 ]
digits = list(map(int, reversed(str(s))))
result = 1
for i in range(log_s):
    c = (i - 1 >= 0 and is_carried[i - 1])
    cnt = 0
    for a in range(10):
        b = digits[i] - a - c
        cnt += bool(b < 0) == bool(is_carried[i])
    result *= cnt
print(result)
```
