---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/200/
  - /blog/2016/01/16/yuki-200/
date: 2016-01-16T04:17:03+09:00
tags: [ "competitive", "writeup", "yukicoder", "greedy" ]
---

# Yukicoder No.200 カードファイト！

## [No.200 カードファイト！](http://yukicoder.me/problems/297)

### 解法

簡単な貪欲で解ける。

### 実装

``` python
#!/usr/bin/env python3
n = int(input())
a = int(input())
b = list(map(int,input().split()))
c = int(input())
d = list(map(int,input().split()))
ans = 0
xs, ys = [], []
for _ in range(n):
    if not len(xs): xs = list(sorted(b))
    if not len(ys): ys = list(sorted(d))
    for x in xs:
        zs = list(filter(lambda y: y < x, ys))
        if len(zs):
            xs.remove(x)
            ys.remove(max(zs))
            ans += 1
            break
    else:
        xs.remove(xs[0])
        ys.remove(ys[-1])
print(ans)
```
