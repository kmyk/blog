---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/18/
  - /blog/2016/01/22/yuki-18/
date: 2016-01-22T19:52:02+09:00
tags: [ "compeititve", "writeup", "yukicoder", "brainfuck" ]
---

# Yukicoder No.18 うーさー暗号

## [No.18 うーさー暗号](http://yukicoder.me/problems/59)

brainfuck向きの問題。
ひとつ気を付ける点があって、何文字目であるかのカウンタをoverflowさせるとwaが生える。

``` brainfuck
>>>>>
,----------[ while not newline
    >+++++++++[<------>-]< a is one
    <<<
        + inc counter
        <<+++++[>+++++<-]>+> set 26
        [>+<-]>[<+<->>-]< calc difference between 26
        <<+>[<[-]>-]> negate
        <<[- if overflow
            >>[-]<< set 0
        ]>>
        [>+>+<<-]>[<+>-]>> dup counter
    <[ counter times do
        >- decr
        [>+>+<<-]>[<+>-]+>[<[-]>-]<< calc is zero
        >[- if underflow
            +++++[<+++++>-]<+> set z 26
        ]<
        <
    -]>
    >++++++++[<++++++++>-]< add a
    .
,----------]
++++++++++.
```
