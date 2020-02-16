---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc-068-c/
  - /blog/2017/05/16/arc-068-c/
date: "2017-05-16T21:32:37+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc068/tasks/arc068_a" ]
---

# AtCoder Regular Contest 068: C - X: Yet Another Die Game

部内でやったら誤読率$30$%ぐらいでした。

-   好きな面を上にして始めてよい
-   毎回好きな方向に転がしてよい

``` python
#!/usr/bin/env python3
x = int(input())
cnt = 0
cnt += x // (6 + 5) * 2
x %= (6 + 5)
if x >= 1:
    cnt += 1
    x -= 6
    if x >= 1:
        cnt += 1
        x -= 5
assert - 5 <= x <= 0
print(cnt)
```
