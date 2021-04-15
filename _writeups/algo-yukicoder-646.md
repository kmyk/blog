---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/646/
  - /blog/2018/02/27/yuki-646/
date: "2018-02-27T09:11:48+09:00"
tags: [ "competitive", "writeup", "yukicoder", "brainfuck" ]
"target_url": [ "https://yukicoder.me/problems/no/646" ]
---

# Yukicoder No.646 逆ピラミッド

なんだか汚ないコードになった。
プロに見せると半分くらいに縮みそうで怖い。
cheatはなしで書いたがあってもあまり変わらないはず。

## implementation

portable $152$byte

``` brainfuck
+[-[>+>+<<-]>>>,+]
<-[<<<[-----<<<]>>[>>>]<<-]
<[<<<]>>>>
>>>[<<<---[>>>++++++++++<<<-]>>>>>>]<<<---
[[>>[<<<<+>]>>>[<[>.<-]>>>>]<<+<<<-]>>>[<<<+>>>-]<.<<-]
```

入力をふたつに複製、改行文字をもとに文字から整数にキャスト、それらを畳んで$N$をbyteに乗せ、あとは2重ループ
