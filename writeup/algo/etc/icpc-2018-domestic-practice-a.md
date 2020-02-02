---
layout: post
title: "ACM-ICPC 2018 模擬国内予選: A. 改元"
date: 2018-07-01T23:59:00+09:00
tags: [ "competitive", "writeup", "icpc-domestic" ]
"target_url": [ "http://acm-icpc.aitea.net/index.php?2018%2FPractice%2F%E6%A8%A1%E6%93%AC%E5%9B%BD%E5%86%85%E4%BA%88%E9%81%B8%2F%E5%95%8F%E9%A1%8C%E6%96%87%E3%81%A8%E3%83%87%E3%83%BC%E3%82%BF%E3%82%BB%E3%83%83%E3%83%88" ]
---

## note

自明問なのだけど勘違いと目diffミスにより1 WA。
要反省。
ちゃんとdiff (1)を使いましょう。

## 実装

``` python
#!/usr/bin/env python3
import sys
for line in sys.stdin:
    if line.strip() == '#':
        break
    name, y, m, d = line.split()
    y, m, d = map(int, [ y, m, d ])
    if (y, m, d) >= (31, 5, 1):
        y -= 30
        name = '?'
    print(name, y, m, d)
```
