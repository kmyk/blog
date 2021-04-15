---
layout: post
redirect_from:
  - /writeup/algo/atcoder/kupc-2017-a/
  - /blog/2017/10/22/kupc-2017-a/
date: "2017-10-22T13:33:20+09:00"
tags: [ "competitive", "writeup", "kupc", "atcoder", "greedy" ]
"target_url": [ "https://beta.atcoder.jp/contests/kupc2017/tasks/kupc2017_a" ]
---

# Kyoto University Programming Contest 2017: A - Credits

## solution

整列して大きい方から貪欲に取る。$O(N \log N)$。

単位は多めに取っても大丈夫なので注意。
最近競プロを始めた友人氏がこの誤読で落としていた。

## implementation

``` python
#!/usr/bin/env python3
n, k = map(int, input().split())
a = list(map(int, input().split()))
if sum(a) < k:
    print(-1)
else:
    a.sort(reverse=True)
    for i, a_i in enumerate(a):
        k -= a_i
        if k <= 0:
            break
    print(i + 1)
```
