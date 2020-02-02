---
layout: post
alias: "/blog/2017/04/05/abc-057-c/"
date: "2017-04-05T16:20:41+09:00"
title: "AtCoder Beginner Contest 057: C - Digits in Multiplication"
tags: [ "competitive", "writeup", "atcoder", "abc" ]
"target_url": [ "https://beta.atcoder.jp/contests/abc057/tasks/abc057_c" ]
---

深く考えず素因数の数$k$に対し$O(2^k)$したけど、想定は素因数分解も不要の$O(\sqrt{N})$だった。
Standard MLの練習に集中してたのになんだか騙し討ちでも喰らった気分。

## implementation

``` sml
fun sievePrimes(n) =
let
  val isPrime = Array.array(n, true)
  fun fill(i, j) =
    if j < n
      then ( Array.update(isPrime, j, false) ; fill(i, j+i) )
      else ()
  fun go(i) =
    if i = Array.length isPrime
      then ()
      else if not(Array.sub(isPrime, i))
        then go(i+1)
        else ( fill(i, 2*i) ; go(i+1) )
in
  Array.update(isPrime, 0, false) ;
  Array.update(isPrime, 1, false) ;
  go(2) ;
  isPrime
end

fun listPrimes(n) =
let
  val primes = sievePrimes(n)
  val primes = Array.foldli (fn (i, isPrime, acc) => if isPrime then i :: acc else acc) [] primes
  val primes = Vector.fromList(List.rev(primes))
in
  primes
end

fun factorize(n) =
let
  val primes = listPrimes( ceil(Math.sqrt(Real.fromLargeInt(n))) + 3 )
  val factors = ref []
  val n = ref n
in
  Vector.app (fn (p) =>
    let
      val p = Int.toLarge(p)
    in
      while !n mod p = 0 do (
        factors := p :: !factors ;
        n := !n div p
      )
    end
    ) primes ;
  if !n <> 1 then factors := !n :: !factors else () ;
  List.rev(!factors)
end

fun digitLength(n) =
let
  fun go(0, acc) = acc
    | go(n, acc) = go(n div 10, acc + 1)
in
  go(n : LargeInt.int, 0)
end

fun solve(n) =
let
  fun go([], a, b) = Int.max(digitLength(a), digitLength(b))
    | go(p :: qs, a, b) = Int.min(go(qs, p * a, b), go(qs, a, p * b))
  val factors = factorize(n)
in
    go(factors, 1, 1)
end

fun readInt() = TextIO.scanStream (LargeInt.scan StringCvt.DEC) TextIO.stdIn
val SOME n = readInt()
val () = print(Int.toString(solve(n)) ^ "\n")
```
