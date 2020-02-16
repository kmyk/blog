---
layout: post
alias: "/blog/2015/11/21/code-festival-2015-final-a/"
date: 2015-11-21T17:18:39+09:00
tags: [ "competitive", "writeup", "codefestival", "atcoder" ]
---

# CODE FESTIVAL 2015 決勝 A - コード川柳

本番中に軽くgolfしたのを投げた。これを書くにあたってopenの方を見たら抜かれていた。

<!-- more -->

## [A - コード川柳](https://beta.atcoder.jp/contests/code-festival-2015-final-open/tasks/codefestival_2015_final_a) {#a}

### 問題

文字列が3つ与えられる。長さが5 7 5の形になっているか答えよ。

### 実装

``` perl
print(<>=~m/^.{5} .{7} .{5}$/?'':in,valid,$/)
```
