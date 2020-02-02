---
layout: post
alias: "/blog/2017/12/31/arc-085-c/"
title: "AtCoder Regular Contest 085: C - HSI"
date: "2017-12-31T16:04:25+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "guessing" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc085/tasks/arc085_a" ]
---

問題文が難しい。ただし自分なら分かりやすい文章に直せるかどうかについては言及していないことに注意。そもそも分かりやすく書けたらC問題ではなくなりそう。

<blockquote class="twitter-tweet" data-lang="ja"><p lang="ja" dir="ltr">C:(経験とエスパー)<br>D:高々最後2個しか使わん<br>E:残り8ケースまで追い詰めるも死<br>F:█</p>&mdash; fal_rnd@傍観 (@fal_rnd) <a href="https://twitter.com/fal_rnd/status/929343584981065728?ref_src=twsrc%5Etfw">2017年11月11日</a></blockquote>
<script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

<blockquote class="twitter-tweet" data-lang="ja"><p lang="ja" dir="ltr">C なんかエスパーすると((1900*m+100*(n-m))&lt;&lt;m)という式が出てくる<br>D なんかエスパーするとmax(abs(w-a[n-1]),abs(a[n-1]-a[n-2]))という式が出てくる<br>E 実験をすると35まで全探索できることと35以上でlcmが100以下のペアがないことがわかるのではい</p>&mdash; beet (@beet_aizu) <a href="https://twitter.com/beet_aizu/status/929343085988823041?ref_src=twsrc%5Etfw">2017年11月11日</a></blockquote>
<script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

## solution

$(1900M + 100(N - M)) \cdot 2^M$。$O(1)$。

## implementation

``` python
#!/usr/bin/env python3
n, m = map(int, input().split())
print((1900 * m + 100 * (n - m)) * 2 ** m)
```
