---
layout: post
redirect_from:
  - /writeup/algo/atcoder/abc_051_c/
  - /writeup/algo/atcoder/abc-051-c/
  - /blog/2017/01/07/abc-051-c/
date: "2017-01-07T22:12:34+09:00"
tags: [ "competitive", "writeup", "atcoder", "abc" ]
"target_url": [ "https://beta.atcoder.jp/contests/abc051/tasks/abc051_c" ]
---

# AtCoder Beginner Contest 051: C - Back and Forth

ロボット掃除機などの経路決定の際に、細かいグリッドに分けて軸平行に繋いでグラフを作るとギザギザに動いて一見最短距離のような経路とそうでない経路の距離が同じになって困る、という話が思い出された。

## solution

軸平行にしか動けないのでどう動いても距離は同じで、斜めに動く必要はない。

## implementation

``` python
#!/usr/bin/env python3
sx, sy, tx, ty = map(int, input().split())
x = tx - sx
y = ty - sy
s = ''
s += 'U' * y + 'R' * x
s += 'D' * y + 'L' * x
s += 'L' + 'U' * (y+1) + 'R' * (x+1) + 'D'
s += 'R' + 'D' * (y+1) + 'L' * (x+1) + 'U'
print(s)
```
