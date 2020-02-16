---
layout: post
alias: "/blog/2016/11/14/agc-007-b/"
date: "2016-11-14T03:47:56+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc007/tasks/agc007_b" ]
---

# AtCoder Grand Contest 007: B - Construct Sequences

試しに図を書いてみた回。

## solution

これを:
![](/blog/2016/11/14/agc-007-b/foo.svg)

こうすると:
![](/blog/2016/11/14/agc-007-b/bar.svg)

こうなる:
![](/blog/2016/11/14/agc-007-b/baz.svg)

## implementation

``` python
#!/usr/bin/env python3
n = int(input())
ps = list(map(int,input().split()))
imos = [None] * n
for i, p in enumerate(ps):
    imos[p-1] = i
a = [ 0 ]
b = [ 0 ]
for i in range(n):
    a += [ a[-1] + 1 + imos[i]     ]
    b += [ b[-1] + 1 + imos[n-i-1] ]
print(*a[1:])
print(*reversed(b[1:]))
```
