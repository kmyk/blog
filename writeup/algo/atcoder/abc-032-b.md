---
layout: post
alias: "/blog/2016/02/22/abc-032-b/"
title: "AtCoder Beginner Contest 032 B - 高橋君とパスワード"
date: 2016-02-22T21:44:12+09:00
tags: [ "competitive", "writeup", "atcoder", "abc" ]
---

sedしようと思ったけど簡単ではなさそうだったので諦めた。
`n`から長さ$n$`.`の繰り返しを作って、と思ったが、eval的なあれが何もなかったので駄目だった。

brainfuckで大きめのcellの処理系なら、rolling-hash的なことを上手くやればできそう。

## [B - 高橋君とパスワード](https://beta.atcoder.jp/contests/abc032/tasks/abc032_b)

``` python
#!/usr/bin/env python3
s = input()
k = int(input())
ts = set()
for i in range(len(s)):
    t = s[i:i+k]
    if len(t) != k:
        break
    ts.add(t)
print(len(ts))
```
