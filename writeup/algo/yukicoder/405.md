---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/405/
  - /blog/2016/10/08/yuki-405/
date: "2016-10-08T02:03:53+09:00"
tags: [ "competitive", "writeup", "yukicoder" ]
"target_url": [ "http://yukicoder.me/submissions/122425" ]
---

# Yukicoder No.405 ローマ数字の腕時計

時計のローマ数字の$4$は`IV`でなくて`IIII`というの知らなかった。
よく見たら手元の時計もそうなっており驚き。

問題はgolf向きだけど今日はdcがしたい気分なのでパスです。

``` python
#!/usr/bin/env python3
f = 'I II III IIII V VI VII VIII IX X XI XII'.split()
s1, t = input().split()
s2 = f[(f.index(s1) + int(t)) % len(f)]
print(s2)
```
