---
layout: post
redirect_from:
  - /writeup/algo/codeforces/313-a/
  - /blog/2015/12/03/cf-313-a/
date: 2015-12-03T22:42:22+09:00
tags: [ "codeforces", "competitive", "writeup" ]
---

# Codeforces Round #186 (Div. 2) A. Ilya and Bank Account

やるだけ

## [A. Ilya and Bank Account](http://codeforces.com/contest/313/problem/A) {#a}

``` python
#!/usr/bin/env python3
s = input()
y = int(s)
for i in [1,2]:
    t = s[:len(s)-i] + s[len(s)-i+1:]
    if len(t) and t != '-':
        x = int(t)
        y = max(x, y)
print(y)
```
