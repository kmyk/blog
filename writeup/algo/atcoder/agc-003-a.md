---
layout: post
redirect_from:
  - /blog/2016/08/21/agc-003-a/
date: "2016-08-21T23:55:16+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc", "sed" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc003/tasks/agc003_a" ]
---

# AtCoder Grand Contest 003 A - Wanna go back home

提出時に貼り付けをミスして$1$WA。ペナルティが効いてくる回だったので悲しい。

## solution

必ず正の距離動く。なので、`N`と`S`のちょうど一方のみ含む、`E`と`W`のちょうど一方のみ含む、という場合は`No`で、そうでない場合は`Yes`。

## implementation

``` sed
#!/bin/sed -f
/N/ { /S/ ! b no }
/W/ { /E/ ! b no }
/S/ { /N/ ! b no }
/E/ { /W/ ! b no }
s/.*/Yes/
N
: no
s/.*/No/
```
