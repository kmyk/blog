---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/514/
  - /blog/2017/05/09/yuki-514/
date: "2017-05-09T21:47:06+09:00"
tags: [ "competitive", "writeup", "yukicoder", "reactive" ]
"target_url": [ "http://yukicoder.me/problems/no/514" ]
---

# Yukicoder No.514 宝探し３

>   ハッタリ問題なので星３にしましたが実質星２くらいと思っています。

いい感じにやられかけました。

## solution

高々$3$回の質問で十分。$O(1)$。

空間が正方形領域で距離がManhattan距離というのが効く。
正方形の隣合う隅を$2$つ聞けば、それぞれ対角方向な座標軸への成分を答えるので、元の座標軸での答えも求まる。
この手のもので心配なのは菱形の境界線が被る場合だが、菱形の面倒な向きの変は常に領域外なので安心。

## implementation

``` python
#!/usr/bin/env python3
import sys
def d(x, y):
    print(x, y)
    sys.stdout.flush()
    result = int(input())
    if result == 0:
        sys.exit(0)
    return result
limit = 1000000000
d1 = d(0, 0)
d2 = d(limit, 0)
x = (+ limit + d1 - d2) // 2
y = (- limit + d1 + d2) // 2
d(x, y)
assert False # already exited
```
