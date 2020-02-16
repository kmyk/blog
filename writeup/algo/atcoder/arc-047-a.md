---
layout: post
alias: "/blog/2016/01/16/arc-047-a/"
date: 2016-01-16T22:40:19+09:00
tags: [ "competitive", "writeup", "atcoder", "arc" ]
---

# AtCoder Regular Contest 047 A - タブの開きすぎ

## [A - タブの開きすぎ](https://beta.atcoder.jp/contests/arc047/tasks/arc047_a) {#a}

やるだけ。なのでbefungeで書いてみた。しかし末尾の空白で拒絶されやる気を削がれ、B以降が話題になっていたこともあって、pythonでさくっと書き直した。

``` python
#!/usr/bin/env python3
n, l = map(int,input().split())
s = input()
ans, t = 0, 1
for c in s:
    t += { '+': 1, '-': -1 }[c]
    if t > l:
        ans, t = ans+1, 1
print(ans)
```
