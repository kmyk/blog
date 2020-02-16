---
layout: post
alias: "/blog/2017/12/08/abc-076-b/"
date: "2017-12-08T07:24:11+09:00"
tags: [ "competitive", "writeup", "atcoder", "abc", "greedy" ]
"target_url": [ "https://beta.atcoder.jp/contests/abc076/tasks/abc076_b" ]
---

# AtCoder Beginner Contest 076: B - Addition and Multiplication

## solution

貪欲。$O(N)$。

関数$A = \lambda x. 2x$と関数$B = \lambda x. x + K$はいずれも単調増加である。これにより貪欲に結果の小さい方を使っていけばいいことが分かる。

## implementation

``` perl
#!/usr/bin/perl
$n=<>;$k=<>;$a+=$a>$k?$k:$a||2while$n--;print$a
```
