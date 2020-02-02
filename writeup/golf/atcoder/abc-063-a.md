---
layout: post
alias: "/blog/2017/06/12/abc-063-a/"
date: "2017-06-12T15:39:25+09:00"
title: "AtCoder Beginner Contest 063: A - Restricted"
tags: [ "competitive", "writeup", "atcoder", "abc", "sed", "golf" ]
"target_url": [ "https://beta.atcoder.jp/contests/abc063/tasks/abc063_a" ]
---

$102$byte。

``` sed
#!/bin/sed -f
:
s/ \w/&987654321 /
s/ \(.\).*\1\(.\).*/-\2/
/9-/cerror
s/.-/&123456789;/
s/\(.\)-.*\1\(.\).*;/\2 /
t
```

なおテストケースが$8$個なので全部割って`/A B/cD;/A B/cD;/A B/cD;/A B/cD;cerror`みたいにした方が縮む。
