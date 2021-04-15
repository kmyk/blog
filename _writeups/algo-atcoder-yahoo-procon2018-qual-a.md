---
layout: post
redirect_from:
  - /writeup/algo/atcoder/yahoo-procon2018-qual-a/
  - /blog/2018/02/14/yahoo-procon2018-qual-a/
date: "2018-02-14T20:15:23+09:00"
tags: [ "competitive", "writeup", "atcoder", "yahoo-procon" ]
"target_url": [ "https://beta.atcoder.jp/contests/yahoo-procon2018-qual/tasks/yahoo_procon2018_qual_a" ]
---

# 「みんなのプロコン 2018」: A - yahoo

## implementation

sedは早解きに最適

``` sed
#!/bin/sed -f
/yah\(.\)\1/cYES
cNO
```
