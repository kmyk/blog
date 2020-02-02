---
layout: post
alias: "/blog/2016/07/04/abc-041-a/"
date: "2016-07-04T04:49:51+09:00"
title: "AtCoder Beginner Contest 041 A - 添字"
tags: [ "competitive", "writeup", "atcoder", "abc", "golf", "sed", "brainfuck" ]
"target_url": [ "https://beta.atcoder.jp/contests/abc041/tasks/abc041_a" ]
---

## implementation

### sed 75byte

``` sed
#!/bin/sed -f
N
:
s/[1-9]/&S/g
y/0123456789/,012345678/
s/S,/9S/
t
/SS/s/\<.//g
t
s/.//2g
```

抜き返したはずだったのに、%20さんに$2$byte縮められてしまった(<https://beta.atcoder.jp/contests/abc041/submissions/791648>)

### brainfuck 107byte

``` brainfuck
#!/usr/bin/env bf
>>
+[>,----------]
<[++++++++++<]
0 0* 11 s s s s s s
#
-[
    +[+
        <----[>++++++++++<-]>
        [<+>-]
    ]
,----------]
n *0 11 s s s s s s
<[-[>+<-]>>[-]<]
*0 0 c s s s s s
>>.
<++++++++++.
```

angelさんが(おそらくかなり余力を残した上での)$112$byteを提出している(<https://beta.atcoder.jp/contests/abc041/submissions/791532>)
