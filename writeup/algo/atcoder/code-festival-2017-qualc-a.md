---
layout: post
alias: "/blog/2018/01/01/code-festival-2017-qualc-a/"
title: "CODE FESTIVAL 2017 qual C: A - Can you get AC?"
date: "2018-01-01T12:14:00+09:00"
tags: [ "competitive", "writeup", "codefestival", "sed", "golf" ]
"target_url": [ "https://beta.atcoder.jp/contests/code-festival-2017-qualc/tasks/code_festival_2017_qualc_a" ]
---

早解きの意味でもsed一択。

## implementation

``` sed
#!/bin/sed -f
/AC/cYes
cNo
```
