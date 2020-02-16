---
layout: post
redirect_from:
  - /blog/2017/07/14/icpc-2017-domestic-b/
date: "2017-07-14T23:50:35+09:00"
tags: [ "competitive", "writeup", "icpc", "icpc-domestic", "python" ]
---

# ACM-ICPC 2017 国内予選: B. ほとんど同じプログラム

B問題 ほとんど同じ プログラム。

本番ではチームメンバーに任せた。C++で書いて$1$WAしていたようだ。

## solution

指示された通り実装する。$O(\|S\|)$。

Pythonを使うべき。

## implementation

``` python
#!/usr/bin/env python3
IDENTICAL = 'IDENTICAL'
CLOSE = 'CLOSE'
DIFFERENT = 'DIFFERENT'
while True:
    s = input()
    if s == '.':
        break
    t = input()
    if s == t:
        result = IDENTICAL
    else:
        result = CLOSE
        modified = 0
        for i, (a, b) in enumerate(zip(s.split('"') + [ None ], t.split('"') + [ None ])):
            if a is None and b is None:
                pass
            elif a is None or b is None:
                result = DIFFERENT
            else:
                if a != b:
                    modified += 1
                    if i % 2 == 0 or modified >= 2:
                        result = DIFFERENT
    print(result)
```
