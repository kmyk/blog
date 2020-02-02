---
layout: post
alias: "/blog/2017/04/05/abc-053-b/"
date: "2017-04-05T03:49:36+09:00"
title: "AtCoder Beginner Contest 053: B - A to Z String"
tags: [ "competitive", "writeup", "atcoder", "abc" ]
"target_url": [ "https://beta.atcoder.jp/contests/abc053/tasks/abc053_b" ]
---

`string`の中身は配列っぽいので普通にloopを回したいけど、逆方向のいい感じのがないので畳み込んだ。

## implementation

``` sml
fun solve(s) =
  let
    val SOME (i, _) = CharVector.findi (fn (i, c) => c = #"A") s
    val SOME  j     = CharVector.foldri (fn (i, c, acc) => if acc = NONE andalso c = #"Z" then SOME i else acc) NONE s
  in
    j - i + 1
  end

val SOME s = TextIO.inputLine TextIO.stdIn
val () = print(Int.toString(solve(s)) ^ "\n")
```
