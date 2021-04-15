---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/83/
  - /blog/2017/01/19/yuki-83/
date: "2017-01-19T09:04:56+09:00"
tags: [ "competitive", "writeup", "yukicoder" ]
"target_url": [ "http://yukicoder.me/problems/no/83" ]
---

# Yukicoder No.83 最大マッチング

星$1$のなかで星が最も付いてる問題だった。

## solution

桁数を最優先する。$4$本で作れる`11`は他のどの$1$桁の数字より大きい。$3$本余った場合は`7`を作る。出力長を無視すれば$O(1)$。

## implementation

``` python
#!/usr/bin/env python3
n = int(input())
if n % 2 == 0:
    s = '1' * (n//2)
else:
    s = '7' + '1' * (n//2 - 1)
print(s)
```
