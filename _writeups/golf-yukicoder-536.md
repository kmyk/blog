---
layout: post
redirect_from:
  - /writeup/golf/yukicoder/536/
  - /blog/2017/08/27/yuki-536/
date: "2017-08-27T01:04:06+09:00"
tags: [ "competitive", "writeup", "yukicoder", "golf", "brainfuck" ]
"target_url": [ "https://yukicoder.me/problems/no/536" ]
---

# Yukicoder No.536 人工知能

## solution

$O(N)$。
末尾$2$文字を$x, y$として$2x - y = \mathrm{ord}('Y')$かどうかで分岐。
`xy-AI`となるように並べておいて、真なら$3$文字目から、偽なら$0$文字目から出力する感じで。

## implementation

整形して$116$byte。
cheat。`^@`はnull文字。末尾改行なし。

``` c++
#!/usr/bin/env bfi
+[-<+]
+[->,+]
<[-]<<[>>+<<-]>
[<<[<]<+<<+>>>>[>]>-]
<<[<]>[.>]+>>
[<<[<]<--<+>>>[>]>-]
<+[<]
<[<[.<]>[>]]
<[<]
<[.<]
^@IA^@-^@^@Y
```
