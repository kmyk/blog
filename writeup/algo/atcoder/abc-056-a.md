---
layout: post
redirect_from:
  - /blog/2017/04/05/abc-056-a/
date: "2017-04-05T02:37:03+09:00"
tags: [ "competitive", "writeup", "atcoder", "abc" ]
"target_url": [ "https://beta.atcoder.jp/contests/abc056/tasks/abc056_a" ]
---

# AtCoder Beginner Contest 056: A - HonestOrDishonest

急にStandard MLしたくなったので。文字literalが`#"c"`なのが独特。

## implementation

``` sml
fun solve(#"H", b) = b
|   solve(#"D", #"H") = #"D"
|   solve(#"D", #"D") = #"H"

fun readChar() = TextIO.scanStream Char.scan TextIO.stdIn
val SOME a = readChar()
val SOME #" " = readChar()
val SOME b = readChar()
val () = print(Char.toString(solve(a, b)) ^ "\n")
```
