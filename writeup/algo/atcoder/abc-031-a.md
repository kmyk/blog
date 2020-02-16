---
layout: post
redirect_from:
  - /blog/2015/11/21/abc-031-a/
date: 2015-11-21T23:09:34+09:00
tags: [ "competitive", "writeup", "atcoder", "abc", "befunge" ]
---

# AtCoder Beginner Contest 031 A - ゲーム

brainfuckじゃ少し面倒そうだったからbefungeを選んで書いたが、末尾に空白入れるとだめとか言われてしまった。桁毎に出力する部分を書いたが、単にバグらせたり、自前処理系のバグを掘り出したりして、かなり時間がかかってしまった。2行目以降は全て出力のための処理です。

## [A - ゲーム](https://beta.atcoder.jp/contests/abc031/tasks/abc031_a) {#a}

``` befunge
&00p&10p00g10g00g10g`#v_\>1+*v  make the answer
vp00\0                ># ^#  <
>00g:!#v_:25*%1+\25*/00pv  split to digits
^   >#  2# 5# *# ,# @#  <  newline
v$     <    0<
>:!#^_1-68*+,^  print digits
```
