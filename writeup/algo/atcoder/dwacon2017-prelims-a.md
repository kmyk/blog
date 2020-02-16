---
layout: post
alias: "/blog/2016/12/17/dwacon2017-prelims-a/"
date: "2016-12-17T22:04:41+09:00"
tags: [ "competitive", "writeup", "atcoder", "dwacon", "golf" ]
"target_url": [ "https://beta.atcoder.jp/contests/dwacon2017-prelims/tasks/dwango2017qual_a" ]
---

# 第3回 ドワンゴからの挑戦状 予選: A - 動画検索

## solution

単に$\max \\{ 0, a + b - n \\}$が答え。

## implementation

awk $21$byte

``` awk
$0=""(0<a=$2+$3-$1)*a
```

### 検討

cielさんの提出, awk $20$byte (<https://beta.atcoder.jp/contests/dwacon2017-prelims/submissions/1030086>):

``` awk
$0=(0<$2+=$3-$1)*$2a
```

awkの`$0=...`の記法はパターン部(`BEGIN`等を置く位置)で副作用を起こし`$0`を変化させ、アクション部(`{ ... }`)の省略により`$0`を出力させるもの。
このためパターン部が整数$0$つまり偽になると出力がなされない。
これを`0 ""`などとして文字列結合演算を与えて文字列`0`にすると真になり出力される。
このための文字列結合演算を未使用の変数$a$を使って引き起こしている。
