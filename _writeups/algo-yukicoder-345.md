---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/345/
  - /blog/2016/02/26/yuki-345/
date: 2016-02-26T23:45:05+09:00
tags: [ "competitive", "writeup", "yukicoder" ]
---

# Yukicoder No.345 最小チワワ問題

## [No.345 最小チワワ問題](http://yukicoder.me/problems/984)

一回の走査で済む。

``` python
#!/usr/bin/env python3
s = input()
c, cw = None, None
ans = float('inf')
for i in range(len(s)):
    if s[i] == 'c':
        c = i
    elif s[i] == 'w':
        if cw is not None:
            ans = min(ans, i - cw + 1)
        if c is not None:
            cw = c
print([ans, -1][ans == float('inf')])
```
