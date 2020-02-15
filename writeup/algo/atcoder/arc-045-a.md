---
layout: post
alias: "/blog/2015/10/19/arc-045-a/"
title: "AtCoder Regular Contest 045 A - スペース高橋君"
date: 2015-10-19T22:46:52+09:00
tags: [ "atcoder", "arc", "competitive", "writeup", "brainfuck", "sed" ]
---

しばらくぶりのbrainfuck問

<!-- more -->

## [A - スペース高橋君](https://beta.atcoder.jp/contests/arc045/tasks/arc045_a) {#a}

### 問題

``` sh
sed 's/Left/</g ; s/Right/>/g ; s/AtCoder/A/g'
```

### 実装

行数に比して実装は軽め。コピペは多め。

``` brainfuck
>>>
,+[-
    <<<+>>> p 0 0 *n*

    <<<[>+>+<<-]>[<+>-]>[-> p 0 0 *n*
        [>+>+<<-]>[<+>-] p 0 0 n *0* n
        +++++++[>-----------<-]>+ p 0 0 n 0 *n\L*
        [<->[-]]<+[- p 0 0 n *0* 0
            <<<<->>>>
            ++++++[>++++++++++<-]>.[-]<
            ,,,[-]
        ]
        < p 0 0 *n*
    <]> p 0 0 *n*

    <<<[>+>+<<-]>[<+>-]>[-> p 0 0 *n*
        [>+>+<<-]>[<+>-] p 0 0 n *0* n
        +++++++++[>---------<-]>- p 0 0 n 0 *n\R*
        [<->[-]]<+[- p 0 0 n *0* 0
            <<<<->>>>
            ++++++[>++++++++++<-]>++.[-]<
            ,,,,[-]
        ]
        < p 0 0 *n*
    <]> p 0 0 *n*

    <<<[>+>+<<-]>[<+>-]>[-> p 0 0 *n*
        [>+>+<<-]>[<+>-] p 0 0 n *0* n
        ++++++++[>--------<-]>- p 0 0 n 0 *n\A*
        [<->[-]]<+[- p 0 0 n *0* 0
            <<<<->>>>
            <.>
            ,,,,,,[-]
        ]
        < p 0 0 *n*
    <]> p 0 0 *n*

    <<<[->>>
        .
    <<<]>>>
,+]
```