---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/333/
  - /blog/2016/02/11/yuki-333/
date: 2016-02-11T22:11:21+09:00
tags: [ "competitive", "writeup", "yukicoder" ]
---

# Yukicoder No.333 門松列を数え上げ

brainfuckのライブラリのverifyに使えそう、ってちょっと思った。

## [No.333 門松列を数え上げ](http://yukicoder.me/problems/935)

``` python
#!/usr/bin/env python3
a, b = map(int,input().split())
if a < b:
    print(b - 2)
elif a > b:
    print(2000000000 - 1 - b)
```
