---
layout: post
alias: "/blog/2017/04/05/abc-054-b/"
date: "2017-04-05T03:36:37+09:00"
title: "AtCoder Beginner Contest 054: B - Template Matching"
tags: [ "competitive", "writeup", "atcoder", "abc" ]
"target_url": [ "https://beta.atcoder.jp/contests/abc054/tasks/abc054_b" ]
---

入力の取り方もloopの回し方も分からない。もうちょっとすっきり書きたい。

## implementation

``` sml
fun isMatch(n, m, a, b, y, x) =
  let
    val dy = ref 0
    val dx = ref 0
    val found = ref false
  in
    while !dy < m do (
      dx := 0 ;
      while !dx < m do (
        ( if String.sub(Array.sub(a, y + !dy), x + !dx) <> String.sub(Array.sub(b, !dy), !dx) then found := true else () ) ;
        dx := !dx + 1
      ) ;
      dy := !dy + 1
    ) ;
    not (!found)
  end

fun solve(n, m, a, b) =
  let
    val y = ref 0
    val x = ref 0
    val found = ref false
  in
    while !y < n-m+1 do (
      x := 0 ;
      while !x < n-m+1 do (
        ( if isMatch(n, m, a, b, !y, !x) then found := true else () ) ;
        x := !x + 1
      ) ;
      y := !y + 1
    ) ;
    !found
  end

fun readInt() = Option.valOf(TextIO.scanStream (Int.scan StringCvt.DEC) TextIO.stdIn)
fun readString() = Option.valOf(TextIO.inputLine TextIO.stdIn)
val n = readInt()
val m = readInt()
val "\n" = readString()
val a = Array.tabulate(n, fn(i) => String.substring(readString(), 0, n))
val b = Array.tabulate(m, fn(i) => String.substring(readString(), 0, m))
val () = print((if solve(n, m, a, b) then "Yes" else "No") ^ "\n")
```
