---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/395/
  - /blog/2016/07/16/yuki-395/
date: "2016-07-16T00:02:21+09:00"
tags: [ "competitive", "writeup", "yukicoder", "sed" ]
"target_url": [ "http://yukicoder.me/problems/no/395" ]
---

# Yukicoder No.395 永遠の17歳

普通に引き算するだけ。
`17`という文字列が$X$進数で解釈されるためには$X \gt 7$である必要がある。

``` sed
#!/bin/sed -f
:
s/[1-9]/&s/g
y/123456789/012345678/
s/s0/9s/
t
s/0*s\{7\}//
/s\{8\}/!s/.*/-1/
:1
s/s/<<123456789s01>/
s/\(.\)<.*\1\(s*.\).*>/\2/
t1
```
