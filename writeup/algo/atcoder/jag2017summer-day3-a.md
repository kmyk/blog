---
layout: post
redirect_from:
  - /blog/2017/10/03/jag2017summer-day3-a/
date: "2017-10-03T06:58:35+09:00"
tags: [ "competitive", "writeup", "atcoder", "jag-summer" ]
"target_url": [ "https://beta.atcoder.jp/contests/jag2017summer-day3/tasks/jag2017summer_day3_a" ]
---

# Japan Alumni Group Summer Camp 2017 Day 3: A - Star in Parentheses

後からチーム内の練習会で解いた。全体では$6$完。
詳細: <https://not-522.appspot.com/contest/6295146601644032>。

## problem

balancedな括弧の列中に`*`で示された位置のnestの深さを答えよ。

## implementation

``` python
#!/usr/bin/env python3
s = input()
left = s[: s.index('*')]
print(left.count('(') - left.count(')'))
```
