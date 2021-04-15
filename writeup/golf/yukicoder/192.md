---
layout: post
redirect_from:
  - /writeup/golf/yukicoder/192/
  - /blog/2018/02/27/yuki-192/
date: "2018-02-27T10:31:09+09:00"
tags: [ "competitive", "writeup", "yukicoder", "golf", "brainfuck" ]
"target_url": [ "https://yukicoder.me/problems/no/192" ]
---

# Yukicoder No.192 合成数

入力が整数だけど文字列として処理できるので楽なやつ。

## implementation

portable $40$byte

``` brainfuck
+[->,+]
<[-]<[-[->>++<]>[<]<]
<[<]>[.>]>>.
```

左側はみ出しあり $38$byte

``` brainfuck
+[-<<[.[-]]>>>,+]
<<[-[-<<++>]<[>]>]<<.
```
