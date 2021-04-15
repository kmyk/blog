---
layout: post
redirect_from:
  - /writeup/golf/yukicoder/486/
  - /blog/2017/02/24/yuki-486/
date: "2017-02-24T23:57:26+09:00"
tags: [ "competitive", "writeup", "yukicoder", "golf", "sed", "lie" ]
"target_url": [ "https://yukicoder.me/problems/no/486" ]
---

# Yukicoder No.486 3 Straight Win(3連勝)

嘘を吐いてまでgolfしたが、%20さんのperlに敗北した。そのうち撃墜されてしまうはず。

## implementation

嘘解法 $40$byte bash + sed (<https://yukicoder.me/submissions/152438>):

``` sh
#!/bin/bash
sed -e/{^XX/cWe,OOO/cEa,XXX/cWe}st -ecNA
```

普通に実装したやつ:

``` sed
#!/bin/sed -f
:
/^OOO/cEast
/^XXX/cWest
s/.//
t
cNA
```
