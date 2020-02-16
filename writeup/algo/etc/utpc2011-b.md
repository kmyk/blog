---
layout: post
redirect_from:
  - /blog/2017/12/25/utpc2011-b/
date: "2017-12-25T19:10:37+09:00"
tags: [ "competitive", "writeup", "utpc", "atcoder", "aoj" ]
---

# 東京大学プログラミングコンテスト2011: B. (iwi)

-   <http://www.utpc.jp/2011/problems/iwi.html>
-   <https://beta.atcoder.jp/contests/utpc2011/tasks/utpc2011_2>
-   <http://judge.u-aizu.ac.jp/onlinejudge/description.jsp?id=2260>

## solution

左から$i$番目と右から$i$番目を比較して不一致を数える。$O(N)$。

## implementation

``` python
#!/usr/bin/env python3
flip = { 'i': 'i', 'w': 'w', '(': ')', ')': '(' }
s = input()
result = 0
for i in range((len(s) + 1) // 2):
    result += (flip[s[i]] != s[len(s) - i - 1])
print(result)
```
