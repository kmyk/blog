---
layout: post
redirect_from:
  - /writeup/golf/yukicoder/485/
  - /blog/2017/02/24/yuki-485/
date: "2017-02-24T23:57:24+09:00"
tags: [ "competitive", "writeup", "yukicoder", "golf", "awk" ]
"target_url": [ "https://yukicoder.me/problems/no/485" ]
---

# Yukicoder No.485 方程式のお勉強

awk $25$byteで暫定最短を得た。

## implementation

``` awk
#!/usr/bin/awk -f
$0=$2%$1?"NO":$2/$1
```

``` sh
#!/bin/bash
tr - _|dc -e[[NO]]sc?r~0!=cp
```
