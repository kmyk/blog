---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/379/
  - /blog/2016/07/07/yuki-379/
date: "2016-07-07T23:22:54+09:00"
tags: [ "competitive", "writeup", "yukicoder" ]
"target_url": [ "http://yukicoder.me/problems/no/379" ]
---

# Yukicoder No.379 五円硬貨

`瓦斯`は`gas`と読む。

``` python
#!/usr/bin/env python3
n, g, v = map(int,input().split())
print('%.12f' % ((n // 5) * g / v))
```
