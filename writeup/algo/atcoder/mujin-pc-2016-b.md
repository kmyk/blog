---
layout: post
alias: "/blog/2016/02/27/mujin-pc-2016-b/"
date: 2016-02-27T23:48:20+09:00
tags: [ "competitive", "writeup", "atcoder", "mujin-pc", "golf" ]
---

# MUJIN プログラミングチャレンジ B - ロボットアーム / Robot Arm

## [B - ロボットアーム / Robot Arm](https://beta.atcoder.jp/contests/mujin-pc-2016/tasks/mujin_pc_2016_b)

本番

``` python
#!/usr/bin/env python3
import math
def area(r):
    return pow(r,2) * math.pi
a, b, c = map(float,input().split())
r = a + b + c
l = - min(0, a + b - c, a - b + c, - a + b + c)
print('%.12f' % (area(r) - area(l)))
```

rubyで70byte。$r^2\pi - l^2\pi = \pi(r+l)(r-l)$という変形。`12.56637`は$4\pi$。

``` ruby
a,b,c=gets.split.map &:to_f;p 12.56637*((s=a+b+c)-t=[a,b,c,s/2].max)*t
```
