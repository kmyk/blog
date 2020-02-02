---
layout: post
alias: "/blog/2017/12/30/abc-084-a/"
title: "AtCoder Beginner Contest 084: A - New Year"
date: "2017-12-30T23:15:28+09:00"
tags: [ "competitive", "writeup", "atcoder", "abc", "golf", "awk" ]
"target_url": [ "https://beta.atcoder.jp/contests/abc084/tasks/abc084_a" ]
---

awk一択で提出速度の勝負。sedチャンスという見方もある。

## implementation

``` awk
$0=48-$1
```
