---
layout: post
redirect_from:
  - /writeup/algo/atcoder/code-festival-2016-relay-c/
  - /blog/2016/11/30/code-festival-2016-relay-c/
date: "2016-11-30T01:33:20+09:00"
tags: [ "competitive", "writeup", "atcoder", "codefestival" ]
"target_url": [ "https://beta.atcoder.jp/contests/cf16-relay-open/tasks/relay_c" ]
---

# CODE FESTIVAL 2016 Relay: C - 硬度フェスティバル / Kode Festival

おそろしい祭りだ。

## solution

愚直にやって間に合う。$O(2^N)$。

## implementation

``` python
#!/usr/bin/env python3
n = int(input())
a = [ int(input()) for _ in range(2**n) ]
while len(a) != 1:
    b = []
    for i in range(0, len(a), 2):
        if a[i] == a[i+1]:
            b += [ a[i] ]
        else:
            b += [ abs(a[i] - a[i+1]) ]
    a = b
print(*a)
```
