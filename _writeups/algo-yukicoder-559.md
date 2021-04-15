---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/559/
  - /blog/2017/08/25/yuki-559/
date: "2017-08-25T23:58:16+09:00"
tags: [ "competitive", "writeup", "yukicoder", "sed" ]
"target_url": [ "https://yukicoder.me/problems/no/559" ]
---

# Yukicoder No.559 swapAB列

## solution

$O({\|S\|}^2)$回`BA`を`AB`に置換すればよい。$O({\|S\|}^3)$。

## implementation

``` sed
#!/bin/sed -f
:
s/BA\(.*\)/AB\1-/
t
s/\w*/0/
:1
s/-/<<123456789-01>/
s/\s*\(.\)<.*\1\(-*.\).*>/\2/
t1
```
