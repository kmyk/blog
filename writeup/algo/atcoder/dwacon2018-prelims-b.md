---
layout: post
redirect_from:
  - /blog/2018/01/14/dwacon2018-prelims-b/
date: "2018-01-14T03:41:54+09:00"
tags: [ "competitive", "writeup", "atcoder", "dwacon", "sed", "golf", "dp", "regex" ]
"target_url": [ "https://beta.atcoder.jp/contests/dwacon2018-prelims/tasks/dwacon2018_prelims_b" ]
---

# 第4回 ドワンゴからの挑戦状 予選: B - 2525文字列分解

不覚にもコンテスト中はPythonを提出してしまったので後からsedで書き直した。

## implementation

``` sed
#!/bin/sed -f
:
s/$/-/
s/25//g
/25/b
/\w/c-1
s/^/0/
:1
s/-/<<123456789-01>/
s/\(.\)<.*\1\(-*.\).*>/\2/
t1
```

``` python
#!/usr/bin/env python3
def solve(s):
    dp = [ 0, 0 ]
    for c in s:
        if c == '2':
            if dp[0] != 0:
                dp[0] -= 1
            dp[1] += 1
        else:
            assert c == '5'
            if dp[1] == 0:
                return -1
            dp[1] -= 1
            dp[0] += 1
    if dp[1] != 0:
        return -1
    return dp[0]
print(solve(input()))
```
