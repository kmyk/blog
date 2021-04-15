---
layout: post
redirect_from:
  - /writeup/algo/atcoder/kupc-2017-b/
  - /blog/2017/10/22/kupc-2017-b/
date: "2017-10-22T13:33:22+09:00"
tags: [ "competitive", "writeup", "kupc", "atcoder" ]
"target_url": [ "https://beta.atcoder.jp/contests/kupc2017/tasks/kupc2017_b" ]
---

# Kyoto University Programming Contest 2017: B - Camphor Tree

camphor tree はクスノキのこと。カンフルや樟脳と呼ばれるそれの原料にもなる。

## solution

segment木をするときのあれ。登る方向だと選択肢が複数あって面倒だが、降りる方向だと一意なのでそうすればよい。$O(N)$。

## implementation

``` python
#!/usr/bin/env python3
n, s, t = map(int, input().split())
ans = 0
while s < t:
    t //= 2
    ans += 1
if s != t:
    ans = -1
print(ans)
```
