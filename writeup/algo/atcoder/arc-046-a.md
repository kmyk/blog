---
layout: post
redirect_from:
  - /blog/2016/02/02/arc-046-a/
date: 2016-02-02T14:46:05+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "brainfuck" ]
---

# AtCoder Regular Contest 046 A - ゾロ目数

除算なしでいける気がしたから書き初めたが、すぐに除算が必要だと気付いてしまった。しかたがないのでlibraryから`/mod`を召喚して殴った。

## [A - ゾロ目数](https://beta.atcoder.jp/contests/arc046/tasks/arc046_a)

``` brainfuck
>
,----------[ get until newline
    -->++++++[<------>-] make zero based digits
,----------]
<<[>++++++++++<-]> make a number n in single cell from input two digits
- decr
>+++++++++ nine
<[>>+>+<<<-]>>>[<<<+>>>-]<>+<[[-]>-<<[>>+<<-]>+>>>>>+[<<<<[->+>+<<]>[-<+>]>[-<<<<<-[>]>>>>>>>-<<<<<<[<]>>>>]>+>]<<<<<<<[>]>[>[-<<<+>>>]>>>-<<<<<]>->[-]>>>>>[-]<<[<<<<<+>>>>>-]<<<<<>]>[-<<[-]>>]<< divmod
<<+++++++[>+++++++<-]>>+[<.>-] print the answer
++++++++++. newline
```
