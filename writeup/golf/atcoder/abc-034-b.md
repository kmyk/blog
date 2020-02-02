---
layout: post
alias: "/blog/2016/03/12/abc-034-b/"
title: "AtCoder Beginner Contest 034 B - ペア"
date: 2016-03-12T22:46:39+09:00
tags: [ "competitive", "writeup", "atcoder", "brainfuck", "golf" ]
---

## [B - ペア](https://beta.atcoder.jp/contests/abc034/tasks/abc034_b)

### 実装

#### perl

15byte

``` perl
print~-(<>+1^1)
```

最短を貰った

#### brainfuck

-   整数は$[0, 64)$の範囲しか動かない
-   EOFを読まない
-   非負番地は使用しない
-   提出には<https://github.com/kmyk/wrap-brainfuck>を使用

``` brainfuck
input
>>>>> >>>>>
,----------[  until newline
    ->++++++[<------>-]  1 based digit
    >>>>
,----------]
<<<<<
xor
>>+<<  is odd
[>  last digit times
    +  dup
    >
        [>+<-]+>[<->-]<  negate
    <
<-]
>>  is odd
[<++>-]<-  xor
[<+>-]<
uncarry
>>+<<[>+>[-]<<-]>[<+>-]>[-  if digit is minus one  expressed as 0
    <<  eip as flag
    >>+<<[>+>[-]<<-]>[<+>-]>[-<<  while digit is minus one
        ++++++++++ 10  number 9
        <<<<< -  decr next digit
    >>+<<[>+>[-]<<-]>[<+>-]>]<<
    [<<<<<]>>>>>
    >>+<<-[>+>[-]<<-]+>[<+>-]>[-<<  while digit is zero
        -  remove digit
        >>>>>
    >>+<<-[>+>[-]<<-]+>[<+>-]>]<<
    [>>>>>]<<<<<
    >>
]<<
carry
[  for each digit
    >>+++++++++++<<  11  number 10
    [  digit times
        >+  dup
        >-  10 minus digit as 1 based
        [>+>+<<-]
        >[<+>-]
        +>[<->[-]] negate
        [>>+<<-]
        <<<<
    -]
    >[<+>-]
    >[-]>
    [-  if carried
        <<<[-]+  cur digit is 0
        <<<<<
            [>+>+<<-]+>[<+>-]>[<<->>[-]]<<  add a 1 based digit if doesnt exist
            +  incr next digit
        >>>>> >>>
    ]
    <<<
    <<<<<
]
>>>>>
output
[
    >++++++[<++++++++>-]<- .  digit
    >>>>>
]
++++++++++ .  newline
```
