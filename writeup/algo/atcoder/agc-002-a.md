---
layout: post
redirect_from:
  - /blog/2016/07/31/agc-002-a/
date: "2016-07-31T22:58:19+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc002/tasks/agc002_a" ]
---

# AtCoder Grand Contest 002: A - Range Product

主に見るのは距離の偶奇だけなので最下位桁だけ見ればすむ。これはesolang-ableであるが、ratedなので見送り
。

``` python
#!/usr/bin/env python3
a, b = map(int,input().split())
if a <= b < 0:
    ans = (b - a) % 2 and 'Positive' or 'Negative'
elif 0 < a <= b:
    ans = 'Positive'
else:
    ans = 'Zero'
print(ans)
```
