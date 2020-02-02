---
layout: post
alias: "/blog/2017/03/07/yahoo-procon-2017-qual-a/"
date: "2017-03-07T17:21:05+09:00"
title: "「みんなのプロコン」: A - Yahoo"
tags: [ "competitive", "writeup", "atcoder", "yahoo-procon", "golf", "sed", "lie" ]
"target_url": [ "https://beta.atcoder.jp/contests/yahoo-procon2017-qual/tasks/yahoo_procon2017_qual_a" ]
---

golf暫定最短はcielさんの嘘解法sed $25$byteであった。

## implementation

``` python
#!/usr/bin/env python3
print(['NO', 'YES'][sorted(input()) == sorted('yahoo')])
```

``` sed
#!/bin/sed -f
s/y//
s/a//
s/h//
s/o//
s/o//
/./cNO
cYES
```
