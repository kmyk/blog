---
layout: post
redirect_from:
  - /writeup/algo/etc/utpc2011-a/
  - /blog/2017/12/25/utpc2011-a/
date: "2017-12-25T19:10:34+09:00"
tags: [ "competitive", "writeup", "utpc", "atcoder", "aoj" ]
---

# 東京大学プログラミングコンテスト2011: A. プログラミングコンテスト

-   <http://www.utpc.jp/2011/problems/jam.html>
-   <https://beta.atcoder.jp/contests/utpc2011/tasks/utpc2011_1>
-   <http://judge.u-aizu.ac.jp/onlinejudge/description.jsp?id=2259>

この世界観 好き。

## solution

$h$行それぞれについてsumを取りそのmax。$O(hw)$。

## implementation

``` python
#!/usr/bin/env python3
m, n = map(int, input().split())
result = 0
for _ in range(m):
    a_i = list(map(int, input().split()))
    result = max(result, sum(a_i))
print(result)
```
