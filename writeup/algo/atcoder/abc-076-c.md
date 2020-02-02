---
layout: post
alias: "/blog/2017/12/08/abc-076-c/"
title: "AtCoder Beginner Contest 076: C - Dubious Document 2"
date: "2017-12-08T07:24:12+09:00"
tags: [ "competitive", "writeup", "atcoder", "abc", "lie" ]
"target_url": [ "https://beta.atcoder.jp/contests/abc076/tasks/abc076_c" ]
---

## solution

$L = \|S\|$として$O(L^2 \log L)$。

「$T$を配置できる最も後ろの位置に配置して残りを`a`で埋める」だと嘘で、すべて試して最小を取る必要がある。
しかしテストが弱かったらしく前者で通る。私は気付かず前者で通した。

<blockquote class="twitter-tweet" data-lang="ja"><p lang="ja" dir="ltr">Cは、最初、置き換えられる最後方のを置換してあとは a で埋めるのが最善だろって思ってしまったけど、実装した後で<br>?b??<br>ab<br>が<br>abab になってしまうけど、abaa のが良いことに気付いて、候補を全部持ってソートするように変えた。</p>&mdash; しさし (@shisashi) <a href="https://twitter.com/shisashi/status/924273332454690817?ref_src=twsrc%5Etfw">2017年10月28日</a></blockquote>
<script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

## implementation

``` perl
#!/usr/bin/perl
chop($s=<>=~y/?/./r);chop($t=<>);$a=UNRESTORABLE;$p=substr($s,$_,$m=length$t),$t=~/^$p$/?$a=substr($s,0,$_).$t.substr($s,$_+$m):0for 0..length$s;print$a=~y/./a/r
```
