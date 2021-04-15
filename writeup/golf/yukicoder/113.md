---
layout: post
redirect_from:
  - /writeup/golf/yukicoder/113/
  - /blog/2017/01/27/yuki-113/
date: "2017-01-27T17:32:34+09:00"
tags: [ "competitive", "writeup", "yukicoder", "golf", "ruby" ]
"target_url": [ "https://yukicoder.me/problems/no/113" ]
---

# Yukicoder No.113 宝探し

perlではtailsさんに勝てずなのでrubyをした。

## solution

`N` `E` `W` `S`をそれぞれ数えて軸ごとに差をとってhypot。

## implementation

ruby $61$byte

``` ruby
p eval'Math.hypot '+'N-S,E-W'.gsub(/\w/,&gets.method(:count))
```
