---
layout: post
alias: "/blog/2018/02/14/yahoo-procon2018-qual-a/"
title: "「みんなのプロコン 2018」: A - yahoo"
date: "2018-02-14T20:15:23+09:00"
tags: [ "competitive", "writeup", "atcoder", "yahoo-procon" ]
"target_url": [ "https://beta.atcoder.jp/contests/yahoo-procon2018-qual/tasks/yahoo_procon2018_qual_a" ]
---

## implementation

sedは早解きに最適

``` sed
#!/bin/sed -f
/yah\(.\)\1/cYES
cNO
```
