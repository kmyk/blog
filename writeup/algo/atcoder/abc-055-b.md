---
layout: post
alias: "/blog/2017/04/05/abc-055-b/"
date: "2017-04-05T02:51:49+09:00"
tags: [ "competitive", "writeup", "atcoder", "abc" ]
"target_url": [ "https://beta.atcoder.jp/contests/abc055/tasks/abc055_b" ]
---

# AtCoder Beginner Contest 055: B - Training Camp

`LargeInt`と`IntInf`の違いとは。

## implementation

``` sml
fun fact(n) =
  let
    fun go(0, acc) = acc
    |   go(n, acc) = go(n-1, n * acc mod 1000000007)
  in
    Int.fromLarge(go(Int.toLarge(n), 1))
  end

fun readInt() = TextIO.scanStream (Int.scan StringCvt.DEC) TextIO.stdIn
val SOME n = readInt()
val () = print(Int.toString(fact(n)) ^ "\n")
```
