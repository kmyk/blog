---
layout: post
redirect_from:
  - /blog/2017/02/22/hackerrank-university-codesprint-2-separate-the-numbers/
date: "2017-02-22T23:44:01+09:00"
tags: [ "competitive", "writeup", "hackerrank", "codesprint", "university-codesprint" ]
"target_url": [ "https://www.hackerrank.com/contests/university-codesprint-2/challenges/separate-the-numbers" ]
---

# HackerRank University CodeSprint 2: Separate the Numbers

## problem

与えられた文字列が公差$1$の正整数の等差数列(eg. $(9, 10, 11, 12)$)の$10$進表現を文字列結合(eg. `9101112`)したものになっているか判定しその初項を答えよ。

## implementation

先に答えを作って文字列比較すると楽。

``` python
#!/usr/bin/env python3
def solve(s):
    if s.startswith('0'):
        return
    n = len(s)
    for l in range(1, n-1):
        x = int(s[: l])
        t = ''
        y = x
        while len(t) < len(s):
            t += str(y)
            y += 1
        if t == s:
            return x
for _ in range(int(input())):
    s = input()
    x = solve(s)
    if x is not None:
        print('YES', x)
    else:
        print('NO')
```
