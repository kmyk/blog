---
layout: post
redirect_from:
  - /blog/2016/04/30/arc-052-a/
date: 2016-04-30T21:54:52+09:00
tags: [ "competitive", "writeup", "atcoder", "brainfuck", "golf" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc052/tasks/arc052_a" ]
---

# AtCoder Regular Contest 052 A - 何期生？

`+[-[ foo ],----------]`の形式を偶然思い付いて(あるいは思い出して)、これは良いidiomだなと思ってたが、結局は不要だった。

## bash 9byte

``` sh
tr -d A-z
```

## brainfuck 73byte

``` brainfuck
#!/usr/bin/env bf
>+[
    >++++++[<------>>++<-]>  0 c 0 c\48 0 *12
    [<<[>]<<[.>]>->>-]  output if c\48\i is 0
,[>+>>+<<<-]>>>----------]  0 c 0 *c\10
<<.
```

$0 \ge c - 47 \lt 12$なものを集めてきて出力している。
loopの一週目は$266$のような大きな値として見ることができ、無視される。
`[<<[>]<<[.>]>->>-]`は$12$回実行され、$c-48$から引いていって$0$なら出力。
