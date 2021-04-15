---
layout: post
redirect_from:
  - /writeup/golf/atcoder/abc_034_a/
  - /writeup/golf/atcoder/abc-034-a/
  - /blog/2016/03/12/abc-034-a/
date: 2016-03-12T22:46:32+09:00
tags: [ "competitive", "writeup", "atcoder", "brainfuck", "golf" ]
---

# AtCoder Beginner Contest 034 A - テスト

## [A - テスト](https://beta.atcoder.jp/contests/abc034/tasks/abc034_a)

### 実装

#### perl

31byte

``` perl
<>=~/ /;print$`<$'?Better:Worse
```

climpetさんが`/ /`でなく`$"`を使った1byte短いコードを提出していた。

#### brainfuck

-   整数は$[0, 128)$の範囲しか動かない
-   EOFを読まない
-   非負番地は使用しない
-   提出には<https://github.com/kmyk/wrap-brainfuck>を使用

``` brainfuck
input x
>>
,>++++[<-------->-]<[  until space
    <[<++>-]<[>+++++<-]>>  mult ten
    [<+>-]  add
    ++++[<---->-]  offset
,>++++[<-------->-]<]
input y
>>
,----------[  until newline
    <[<++>-]<[>+++++<-]>>  mult ten
    [<+>-]  add
    ++++++[<------>-]<-->  offset
,----------]
x lt y
<+  incr y  for the case y is 0
<+  lt flag
<+  incr x
[>>  x times
    -  decr y
    [>+>+<<-]
    +>[<->[-]]<  negate y
    [  if not y
        <-  lt is false
        <[-]+  x is 1  to avoid to make a negative number
    >>-]
    >>[<<+>>-]<<
<<-]
output
+>>[-]<  if lt
[-<->  then 66 101 116 116 101 114 10
    ++++++++++[
        >++++++
        >++++++++++
        >+++++++++++
        >+++++++++++
        >++++++++++
        >+++++++++++
        >+
    <<<<<<<-]
    >++++++.
    >+.
    >++++++.
    >++++++.
    >+.
    >++++.
    >.
    <<<<<<<
]<[-  else 87 111 114 115 101 10
    ++++++++++[
        >++++++++
        >+++++++++++
        >+++++++++++
        >+++++++++++
        >++++++++++
        >+
    <<<<<<-]
    >+++++++.
    >+.
    >++++.
    >+++++.
    >+.
    >.
    <<<<<<
]
```
