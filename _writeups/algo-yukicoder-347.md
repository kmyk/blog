---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/347/
  - /blog/2016/02/26/yuki-347/
date: 2016-02-26T23:45:14+09:00
tags: [ "competitive", "writeup", "yukicoder" ]
---

# Yukicoder No.347 微分と積分

解くのはあまりおすすめしない問題。
問題を作ること自体は良いことだと思います。

## [No.347 微分と積分](http://yukicoder.me/problems/836)

``` python
#!/usr/bin/env python3
import math
n = int(input())
b = float(input())
ks = list(map(float,input().split()))
def f(k):
    return k * pow(b, k - 1)
def g(k):
    if k == - 1.0: # ok
        return math.log(b)
    else:
        return pow(b, k + 1) / (k + 1)
print(sum(map(f, ks)))
print(sum(map(g, ks)))
```
