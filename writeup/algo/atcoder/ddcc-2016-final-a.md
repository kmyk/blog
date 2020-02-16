---
layout: post
redirect_from:
  - /blog/2016/12/03/ddcc-2016-final-a/
date: "2016-12-03T14:31:45+09:00"
tags: [ "competitive", "writeup", "atcoder", "ddcc" ]
"target_url": [ "https://beta.atcoder.jp/contests/ddcc2016-final/tasks/ddcc_2016_final_a" ]
---

# DISCO presents ディスカバリーチャンネル コードコンテスト2016 本戦: A - 正方形のチップ

## solution

$R \le 100$なので$4R^2 \le 40000$マスぐらいを見れば尽くせる。$O({(\frac{R}{C})}^2)$。

## implementation

``` python
#!/usr/bin/env python3
r, c = map(int, input().split())
cnt = 0
for ly in range(0, r, c):
    for lx in range(0, r, c):
        pred = True
        for y, x in [ (ly, lx), (ly, lx+c), (ly+c, lx), (ly+c, lx+c) ]:
            if y**2 + x**2 > r**2:
                pred = False
                break
        if pred:
            cnt += 1
print(cnt * 4)
```
