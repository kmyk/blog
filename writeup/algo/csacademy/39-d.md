---
layout: post
redirect_from:
  - /writeup/algo/csacademy/39-d/
  - /writeup/algo/cs-academy/39-d/
  - /blog/2017/07/27/csa-39-d/
date: "2017-07-27T03:03:14+09:00"
tags: [ "competitive", "writeup", "csacademy" ]
"target_url": [ "https://csacademy.com/contest/round-39/task/seven-segment-display/" ]
---

# CS Academy Round #39: D. Seven-segment Display

面倒 / やるだけ / コーナーケース。嫌い。

## solution

自明。leading zerosは禁止だが$0$の場合は許され、$K = 6$のとき答えが$0$となることに注意。入出力などを気にしなければ$O(1)$。

## implementation

``` python
#!/usr/bin/env python3
f = { 2: 1, 3: 7, 4: 4, 5: 2, 6: 0, 7: 8, 8: 10, 9: 18, 10: 22, 11: 20, 12: 28, 13: 68, 14: 88, 15: 108, 16: 188, 17: 200, 18: 208, 19: 288, 20: 688, 21: 888, 22: 1088, 23: 1888, 24: 2008, 25: 2088, 26: 2888, 27: 6888, 28: 8888, 29: 10888, 30: 18888, 31: 20088, 32: 20888, 33: 28888, 34: 68888, 35: 88888, 36: 108888, 37: 188888, 38: 200888, 39: 208888, 40: 288888, 41: 688888, 42: 888888, 43: 1088888, 44: 1888888, 45: 2008888, 46: 2088888, 47: 2888888, 48: 6888888, 49: 8888888, }
n = int(input())
if n <= 1:
    result = -1
else:
    result = ''
    while n > 49:
        result += str(f[7])
        n -= 7
    result = str(f[n]) + result
print(result)
```
