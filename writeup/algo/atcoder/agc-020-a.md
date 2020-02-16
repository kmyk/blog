---
layout: post
redirect_from:
  - /blog/2018/02/22/agc-020-a/
date: "2018-02-22T22:20:42+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc", "game" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc020/tasks/agc020_a" ]
---

# AtCoder Grand Contest 020: A - Move and Win

## solution

相手の方へ近付けるのが最適。$N \le 100$なので愚直に書けばよい。$O(N^2)$。$A \gt B$のときに注意。

## implementation

``` python
#!/usr/bin/env python3
n, a, b = map(int, input().split())
if a > b:
    a, b = b, a
    flipped = True
else:
    flipped = False
turn = 0
while True:
    if turn % 2 == 0:
        if a + 1 == b:
            if a == 1:
                break
            else:
                a -= 1
        else:
            a += 1
    else:
        if b - 1 == a:
            if b == n:
                break
            else:
                b += 1
        else:
            b -= 1
    turn += 1
if flipped:
    a, b = b, a
print(['Borys', 'Alice'][turn % 2])
```
