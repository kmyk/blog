---
layout: post
alias: "/blog/2017/11/10/ddcc2017-qual-b/"
date: "2017-11-10T23:33:59+09:00"
title: "DISCO presents ディスカバリーチャンネル コードコンテスト2017 予選: B - 鉛筆"
tags: [ "competitive", "writeup", "atcoder", "ddcc", "horner-method" ]
"target_url": [ "https://beta.atcoder.jp/contests/ddcc2017-qual/tasks/ddcc2017_qual_b" ]
---

## 感想

$f(x) = a\_nx^n + a\_{n-1}x^{n-1} + \dots + a\_1x + a\_0$の$x = x\_0$での値を計算するようなとき、$f(x) = (( \dots (a\_nx + a\_{n-1})x + \dots) x + a\_1) x + a\_0$とすると計算量が落ちるというあれはHorner法というらしいのですが、それだなあと思いながらコードを書きました。

## implementation

``` python
#!/usr/bin/env python3
a, b, c, d = map(int, input().split())
print(((a * 12 + b) * 12 + c) * 12 + d)
```
