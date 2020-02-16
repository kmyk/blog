---
layout: post
redirect_from:
  - /writeup/algo/atcoder/abc-040-b/
  - /blog/2016/06/19/abc-040-b/
date: 2016-06-19T22:55:58+09:00
tags: [ "competitive", "writeup", "atcoder" ]
"target_url": [ "https://beta.atcoder.jp/contests/abc040/tasks/abc040_b" ]
---

# AtCoder Beginner Contest 040 B - □□□□□

## solution

$\operatorname{ans} = \min\_{x + y \le n} (n - x - y + \|x - y\|)$であるが、$x,y$の片方を決めればもう片方の見るべき値は定まるので、片側だけ全探索。
$O(N)$。

## implementation

``` python
#!/usr/bin/env python3
n = int(input())
ans = float('inf')
for y in range(1,n+1):
    x = n // y
    ans = min(ans, n - x * y + abs(x - y))
print(ans)
```
