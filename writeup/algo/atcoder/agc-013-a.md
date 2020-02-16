---
layout: post
redirect_from:
  - /blog/2017/08/09/agc-013-a/
date: "2017-08-09T22:48:07+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc013/tasks/agc013_a" ]
---

# AtCoder Grand Contest 013: A - Sorted Arrays

実装面倒そうだなあと思ったがそうでもなかった。

## solution

端から貪欲に区間に切っていけばよい。$O(N)$。

## implementation

``` python
#!/usr/bin/env python3
n = int(input())
a = list(map(int, input().split()))
result = 1
delta = 0
for i in range(1, n):
    if a[i - 1] < a[i]:
        ndelta = +1
    elif a[i - 1] > a[i]:
        ndelta = -1
    else:
        ndelta = 0
    if delta and ndelta and delta != ndelta:
        result += 1
        delta = 0
    elif not delta:
        delta = ndelta
print(result)
```
