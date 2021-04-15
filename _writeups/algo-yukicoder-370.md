---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/370/
  - /blog/2016/05/24/yuki-370/
date: 2016-05-24T20:51:33+09:00
tags: [ "competitive", "writeup", "yukicoder" ]
"target_url": [ "http://yukicoder.me/problems/780" ]
---

# Yukicoder No.370 道路の掃除

方針は簡単だが、実装は少しだけ間違えやすい。やらかした。

友人らが踏んでいた点として、

-   `for l in range(m - n + 1):`の内側で(`min` `max`による暗黙のものも含む)場合分けをするのが正解。外側で場合分けすると面倒になるようだ。
-   入力はsortされているとは限らない。

``` python
#!/usr/bin/env python3
n, m = map(int,input().split())
d = sorted([int(input()) for i in range(m)])
ans = float('inf')
for l in range(m - n + 1):
    r = l + n - 1
    if d[l] <= d[r] <= 0:
        acc = - d[l]
    elif 0 <= d[l] <= d[r]:
        acc = d[r]
    else:
        assert d[l] <= 0 <= d[r]
        acc = max(- d[l], d[r]) + 2 * min(- d[l], d[r])
    ans = min(ans, acc)
print(ans)
```
