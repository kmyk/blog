---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/244/
  - /blog/2016/06/22/yuki-244/
date: 2016-06-22T04:05:52+09:00
tags: [ "competitive", "writeup", "yukicoder", "sed" ]
"target_url": [ "http://yukicoder.me/problems/no/244" ]
---

# Yukicoder No.244 ★１のグラフの問題

つまり、木

``` sed
#!/bin/sed -f
y/1234567890/0123456789/
s/09/9/
s/^0/1/
```
