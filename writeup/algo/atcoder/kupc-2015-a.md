---
layout: post
alias: "/blog/2015/10/24/kupc-2015-a/"
title: "京都大学プログラミングコンテスト2015 A - 東京都"
date: 2015-10-24T23:55:00+09:00
tags: [ "kupc", "competitive", "writeup", "shellscript", "oneliner" ]
---

本体部分は1行

<!-- more -->

## [A - 東京都](https://beta.atcoder.jp/contests/kupc2015/tasks/kupc2015_a) {#a}

### 問題

文字列から`tokyo`あるいは`kyoto`を計いくつ切り出せるか。

### 解法

貪欲

### 実装

``` sh
#!/bin/sh
read n
for i in `seq $n` ; do
    read line
    echo $line | grep -o 'tokyo\|kyoto' | wc -l
done
```
