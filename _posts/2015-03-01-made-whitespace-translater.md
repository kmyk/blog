---
category: blog
layout: post
title: "whitespace言語の変換器を作った"
date: 2015-03-01T19:55:22+09:00
tags: [ "esolang", "whitespace", "javascript", "web" ]
---

[/works/whitespace-translater](/works/whitespace-translater)

必要に迫られて作った。

-   whitespace
-   `S`/`T`/`\n`で置換したやつ
-   アセンブリ言語的ななにか

の3種を相互変換できる。実行はできない。

<!-- more -->

## whitespaceの簡単な説明と感想

命令が空白文字のみから構成される点が特徴的な言語。言語としては特に面白くなく、数値を2進数で埋め込めるし任意精度整数やサブルーチン機能が使えてしまう。一般のテキストに埋め込む遊びを想定しコードがあまり長くならないように作られたのだろう。本家interpreterはhaskell製。cabalや多くのdistributionのpackage managerからinstallできる。これを書くぐらいなら普通のassembly言語を書きたいと思う。

-   [本家](http://compsoc.dur.ac.uk/whitespace/)
-   [Whitespace - Wikipedia](http://ja.wikipedia.org/wiki/Whitespace)
-   [Rubyist のための他言語探訪 【第 14 回】 Whitespace](http://magazine.rubyist.net/?0022-Legwork)
