---
layout: post
redirect_from:
  - /blog/2017/12/31/utpc-2012-b/
date: "2017-12-31T17:55:49+09:00"
tags: [ "competitive", "writeup", "utpc", "atcoder" ]
"target_url": [ "https://beta.atcoder.jp/contests/utpc2012/tasks/utpc2012_02" ]
---

# 東京大学プログラミングコンテスト2012: B - 残像に口紅を

## solution

後ろから見ていって文字の始めて出現する順番を考え、この逆順に禁止されたいたとすればよい。$O(N)$。

## implementation

``` python
#!/usr/bin/env python3
s = input()
result = ''
for c in list(reversed(s)) + list('ABCDEFGH'):
    if c not in result:
        result = c + result
print(result)
```
