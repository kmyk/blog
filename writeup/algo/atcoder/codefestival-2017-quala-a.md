---
layout: post
alias: "/blog/2017/10/03/codefestival-2017-quala-a/"
date: "2017-10-03T06:36:48+09:00"
title: "CODE FESTIVAL 2017 qual A: A - Snuke's favorite YAKINIKU"
tags: [ "competitive", "writeup", "atcoder", "codefestival", "sed" ]
"target_url": [ "https://beta.atcoder.jp/contests/code-festival-2017-quala/tasks/code_festival_2017_quala_a" ]
---

## implementation

これは本番でもsed一択

``` sed
#!/bin/sed -f
/^YAKI/cYes
cNo
```
