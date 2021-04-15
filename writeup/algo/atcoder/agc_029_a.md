---
layout: post
date: 2018-12-16T04:08:01+09:00
tags: [ "competitive", "writeup", "atcoder", "agc", "inversion-number" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc029/tasks/agc029_a" ]
redirect_from:
  - /writeup/algo/atcoder/agc_029_a/
  - /writeup/algo/atcoder/agc-029-a/
---

# AtCoder Grand Contest 029: A - Irreversible operation

## 解法

### 概要

問題を整理すると $$0, 1$$ のみからなる数列の転倒数を求めるだけになり $$O(N \log N)$$。
値の種類が有限であることを利用すれば $$O(N)$$。

## 実装

``` c++
#!/usr/bin/env python3
s = input()
ans = 0
b = 0
for c in s:
    if c == 'W':
        ans += b
    elif c == 'B':
        b += 1
print(ans)
```
