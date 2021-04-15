---
layout: post
redirect_from:
  - /writeup/algo/atcoder/yahoo-procon2018-qual-b/
  - /blog/2018/02/14/yahoo-procon2018-qual-b/
date: "2018-02-14T20:15:24+09:00"
tags: [ "competitive", "writeup", "atcoder", "yahoo-procon" ]
"target_url": [ "https://beta.atcoder.jp/contests/yahoo-procon2018-qual/tasks/yahoo_procon2018_qual_b" ]
---

# 「みんなのプロコン 2018」: B - オークション

## implementation

$X + 1$を$10^K$で切り上げる方向に割ってから$10^K$かけて戻す。

``` python
#!/usr/bin/env python3
x, k = map(int, input().split())
y = x + 1
y = (y + 10 ** k - 1) // 10 ** k * 10 ** k
print(y)
```
