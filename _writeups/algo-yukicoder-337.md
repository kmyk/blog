---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/337/
  - /blog/2016/01/29/yuki-337/
date: 2016-01-29T23:28:55+09:00
tags: [ "competitive", "writeup", "yukicoder", "brainfuck" ]
---

# Yukicoder No.337 P versus NP

## [No.337 P versus NP](http://yukicoder.me/problems/798)

ちょうど良い難易度

``` brainfuck
>>
,>++++++++[<---->-]<[ get until space
    >
,>++++++++[<---->-]<]
>
,----------[ get until newline
    >
,----------]
<<[>[<+>-]<<]>> sum sign and digits
++++++[<------>-]+<--[>-<[-]]>[- if is zero
    <<<[<]<+>>[>]>> set equal flag
]
<<
<<[>[<+>-]<<]>> sum sign and digits
++++[<---->-]+<-[>-<[-]]>[- if is one
    <<<+>>> set equal flag
]
++++++++[<++++>-]<+ make bang sign
<+<[>-<[-]]>[- if not equal
    >.< put bang sign
]
+++++++[>++++>+<<-]>. put equal sign
>+++. put newline
```
