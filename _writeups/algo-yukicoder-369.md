---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/369/
  - /blog/2016/05/24/yuki-369/
date: 2016-05-24T20:51:28+09:00
tags: [ "competitive", "writeup", "yukicoder" ]
"target_url": [ "http://yukicoder.me/problems/1039" ]
---

# Yukicoder No.369 足し間違い

``` python
#!/usr/bin/env python3
n = int(input())
xs = map(int,input().split())
y = int(input())
print(sum(xs) - y)
```
