---
layout: post
redirect_from:
  - /writeup/golf/atcoder/abc_084_b/
  - /writeup/golf/atcoder/abc-084-b/
  - /blog/2017/12/30/abc-084-b/
date: "2017-12-30T23:15:30+09:00"
tags: [ "competitive", "writeup", "atcoder", "abc", "golf", "perl" ]
"target_url": [ "https://beta.atcoder.jp/contests/abc084/tasks/abc084_b" ]
---

# AtCoder Beginner Contest 084: B - Postal Code

<!-- {% raw %} -->

## solution

正規表現。

## implementation

終了後に改良をしての最終的な提出は以下。
終了後に%20さんが使っていたのを見て思い出して`$%`を使い、climpetさんが嘘解法をしていたのを見てこれも採用した。

``` perl
$%=<>;print<>=~/^\d{$%}-\d/?Yes:No
```

`$%`は`$FORMAT_PAGE_NUMBER` が長い名前で整数型にcastされるのが利点。正規表現中に埋め込むには空白や末尾の改行を落とさねばならない。

<!-- {% endraw %} -->
