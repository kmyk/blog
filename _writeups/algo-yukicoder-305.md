---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/305/
  - /blog/2016/05/31/yuki-305/
date: 2016-05-31T18:20:51+09:00
tags: [ "competitive", "writeup", "yukicoder", "reactive" ]
"target_url": [ "http://yukicoder.me/problems/768" ]
---

# Yukicoder No.305 鍵(2)

## solution

桁ごとに決定していけばよい。
$1$つの桁の決定に高々$10$回の試行が必要で、$10$桁あるので、$100$回のクエリとなり十分間に合う。

前問と共通する注意として、

-   flushを忘れない
-   unlockedが来たらちゃんと止まる

## implementation

``` python
#!/usr/bin/env python3
import sys
key = [None] * 10
for i in range(len(key)):
    best_n = -1
    correct_digit = None
    for j in range(10):
        key[i] = j
        print(''.join([str(c or '0') for c in key]))
        sys.stdout.flush()
        n, result = input().split()
        if result == 'unlocked':
            sys.exit(0)
        n = int(n)
        if best_n < n:
            best_n = n
            correct_digit = j
    key[i] = correct_digit
```
