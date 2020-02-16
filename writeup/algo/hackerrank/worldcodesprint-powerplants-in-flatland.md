---
layout: post
redirect_from:
  - /blog/2016/01/31/hackerrank-worldcodesprint-powerplants-in-flatland/
date: 2016-01-31T01:42:58+09:00
tags: [ "competitive", "writeup", "hackerrank", "world-codesprint" ]
---

# HackerRank World Codesprint: Flatland Space Stations

## [Flatland Space Stations](https://www.hackerrank.com/contests/worldcodesprint/challenges/powerplants-in-flatland)

### 問題

道グラフ$P_n$が与えられ、$m$個の頂点に印が付けられている。
各頂点に関して最も近い印の付いた頂点との距離を求め、その最大値を答えよ。

### 解説

右向きと左向きで2回舐めればよい。

現在地から見て左側にある印の付いた頂点で最も近いものの位置を持ちながら右へ舐める。
現在地から見て右側にある印の付いた頂点で最も近いものの位置を持ちながら左へ舐める。

### 実装

``` python
#!/usr/bin/env python3
n, m = map(int,input().split())
s = set(map(int,input().split()))
l = [float('inf')] * n
p = - float('inf')
for i in range(n):
    if i in s:
        p = i
    l[i] = i - p
r = [float('inf')] * n
p = float('inf')
for i in reversed(range(n)):
    if i in s:
        p = i
    r[i] = p - i
dist = [min(l[i], r[i]) for i in range(n)]
print(max(dist))
```
