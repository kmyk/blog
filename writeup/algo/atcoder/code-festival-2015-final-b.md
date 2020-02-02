---
layout: post
alias: "/blog/2015/11/21/code-festival-2015-final-b/"
title: "CODE FESTIVAL 2015 決勝 B - ダイスゲーム"
date: 2015-11-21T17:18:49+09:00
tags: [ "competitive", "writeup", "codefestival", "atcoder" ]
---

これも本番でgolf。
証明はしていない。

<!-- more -->

## [B - ダイスゲーム](https://beta.atcoder.jp/contests/code-festival-2015-final-open/tasks/codefestival_2015_final_b) {#b}

### 問題

$6$面ダイスを$N$個振る。出目の和として最も確率が高い値を答えよ。複数あればその中で最小の値を答えよ。

### 解法

$3.5$倍して床を取る。ただし$N = 1$の場合はどれも等確率なので$1$が答え。

### 実装

``` perl
print(($_=<>)-1?int$_*7/2:1,$/)
```
