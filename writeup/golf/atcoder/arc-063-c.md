---
layout: post
redirect_from:
  - /blog/2016/11/06/arc-063-c/
date: "2016-11-06T22:48:16+09:00"
tags: [ "competitive", "wirteup", "atcoder", "arc", "golf", "perl" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc063/tasks/arc063_a" ]
---

# AtCoder Regular Contest 063: C - 一次元リバーシ / 1D Reversi

$27$byteで終了時最短であった。HITCON 2016 qualsのregex問の経験が生きた。

``` perl
print s/(.)(?!\1)//g-1for<>
```
