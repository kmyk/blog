---
layout: post
alias: "/blog/2016/02/27/mujin-pc-2016-a/"
title: "MUJIN プログラミングチャレンジ A - MUJIN"
date: 2016-02-27T23:48:17+09:00
tags: [ "competitive", "writeup", "atcoder", "mujin-pc", "golf" ]
---

## [A - MUJIN](https://beta.atcoder.jp/contests/mujin-pc-2016/tasks/mujin_pc_2016_a)

本番書いたやつ。

``` python
#!/usr/bin/env python3
c = input()
print(['Left', 'Right'][c in 'OPKL'])
```

とりあえず書いた31byteのperl。

``` perl
print/[K-P]/?Right:Left,$/for<>
```

angelさんの31byteから1byte縮めた30byte。

``` perl
print<>=~/[K-P]/?Right:Left,$/
```

空白除去して`sed '...'`で包んでbashにして28byte。

``` sed
s/[K-P]/Right/
t
c Left
```

atcoderにsed入るの楽しみ。
