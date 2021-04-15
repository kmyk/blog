---
layout: post
redirect_from:
  - /writeup/golf/yukicoder/436/
  - /blog/2016/10/29/yuki-436/
date: "2016-10-29T00:24:30+09:00"
tags: [ "competitive", "writeup", "yukicoder", "golf", "perl" ]
"target_url": [ "http://yukicoder.me/problems/no/436" ]
---

# Yukicoder No.436 ccw

$\mathrm{ans} = \min \\{ \mathrm{cnt}(\mathrm{c}) - 1, \mathrm{cnt}(\mathrm{w}) \\}$。

``` perl
print y/w//<y/c//?y/w//:~-y/c//for<>
```

[tailsさんの提出](http://yukicoder.me/submissions/126669)が$1$位だった。
`!~`入力を``$` ``と`$'`に分けつつ空文字列にし、それらの各点bit積でminを求め、しかも改行文字によりoff-by-oneもいい感じになっている。
