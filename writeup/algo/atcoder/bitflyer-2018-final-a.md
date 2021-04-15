---
redirect_from:
layout: post
date: 2018-07-02T20:13:38+09:00
tags: [ "competitive", "writeup", "atcoder", "codeflyer" ]
"target_url": [ "https://beta.atcoder.jp/contests/bitflyer2018-final-open/tasks/bitflyer2018_final_a" ]
---

# codeFlyer （bitFlyer Programming Contest）: A - 値札

## note

`math.inf` を使ったらREした。
これは3.5からでAtCoderは現在3.4.3。
CE扱いなら不満はないがREなのは不満。

## implementation

``` python
#!/usr/bin/env python3
acc = float('inf')
for _ in range(int(input())):
    s = input()
    cnt = 0
    while s.endswith('0'):
        s = s[: - 1]
        cnt += 1
    acc = min(acc, cnt)
print(acc)
```
