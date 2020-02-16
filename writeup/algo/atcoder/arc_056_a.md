---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc-056-a/
  - /blog/2016/06/26/arc-056-a/
date: 2016-06-26T00:07:32+09:00
tags: [ "competitive", "writeup", "atcoder", "arc" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc056/tasks/arc056_a" ]
---

# AtCoder Regular Contest 056 A - みんなでワイワイみかん

サンプルが弱かったら時間を溶かしていたかもしれない。

``` python
#!/usr/bin/env python3
a, b, k, l = map(int,input().split())
print((k // l) * b + min((k % l) * a, b))
```
