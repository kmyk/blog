---
layout: post
alias: "/blog/2017/12/31/utpc-2012-a/"
title: "東京大学プログラミングコンテスト2012: A - 2012年12月02日"
date: "2017-12-31T17:55:47+09:00"
tags: [ "competitive", "writeup", "utpc", "atcoder", "golf", "ruby" ]
"target_url": [ "https://beta.atcoder.jp/contests/utpc2012/tasks/utpc2012_01" ]
---

## implementation

最短が落ちていたので拾っておいた。`/`ごとsortしてしまうのがポイント。

``` ruby
s=gets.chars;puts s[0..4].sort==s[5..9].sort&&:yes||:no
```
