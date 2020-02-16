---
layout: post
redirect_from:
  - /blog/2016/01/31/hackerrank-worldcodesprint-save-our-ship/
date: 2016-01-31T01:42:23+09:00
tags: [ "competitive", "writeup", "hackerrank", "world-codesprint" ]
---

# HackerRank World Codesprint: Mars Exploration

brainfuck-ableな問題。

## [Mars Exploration](https://www.hackerrank.com/contests/worldcodesprint/challenges/save-our-ship)

### 問題

`SOS`の繰り返しでできる文字列`SOSSOSSOS...SOS`があった。
しかしいくつかの文字が別の文字で置き換わってしまった。
置き換わったあとの文字列が与えられるので、置き換わった文字の数を答えよ。

### 実装

``` python
#!/usr/bin/env python3
s = input()
ans = 0
for i in range(len(s)//3):
    if s[3*i] != 'S':
        ans += 1
    if s[3*i+1] != 'O':
        ans += 1
    if s[3*i+2] != 'S':
        ans += 1
print(ans)
```
