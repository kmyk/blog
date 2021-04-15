---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc_053_a/
  - /writeup/algo/atcoder/arc-053-a/
  - /blog/2016/05/14/arc-053-a/
date: 2016-05-14T23:02:55+09:00
tags: [ "competitive", "writeup", "atcoder", "arc" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc053/tasks/arc053_a" ]
---

# AtCoder Regular Contest 053 A - ドミノ色塗り

## solution

-   縦向きに置けるのは$H \cdot (W - 1)$個。
-   横向きに置けるのは$(H - 1) \cdot W$個。

足して$2HW - H - W$個。

## implementation

``` python
#!/usr/bin/env python3
h, w = map(int,input().split())
print(2 * h * w - h - w)
```
