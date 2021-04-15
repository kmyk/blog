---
layout: post
redirect_from:
  - /writeup/algo/atcoder/code-festival-2015-final-e/
  - /blog/2015/11/21/code-festival-2015-final-e/
date: 2015-11-21T17:19:03+09:00
tags: [ "competitive", "writeup", "codefestival", "atcoder" ]
---

# CODE FESTIVAL 2015 決勝 E - ショートコーディング

こういう問題は好きです。

Eまで通して、5完でパーカー確定したなあと思った後に、去年はパーカーが結構厳しく60人ぐらいしか貰えてなかったなあと思いだして、パーカーって5完で貰えるというので本当に合ってるのかなとすごく不安になったりした。

<!-- more -->

## [E - ショートコーディング](https://beta.atcoder.jp/contests/code-festival-2015-final-open/tasks/codefestival_2015_final_e) {#e}

### 問題

演算子`-`と`!`のみからなる言語がある。
入力として$-256 \sim 256$の整数が受け取り、演算子を後ろから適用していき、整数を出力する。
演算子は以下のような挙動を持つ。

-   `-`
    -   正負を反転
-   `!`
    -   $0$なら$1$に、それ以外なら$0$に

この言語のプログラムが与えられるので、等価なプログラムで最短のものを出力せよ。

### 解法

演算子は、以下の性質を持つ。

-   `!`より後ろにある`-`は全て無視してよい。
-   `--`と`-`は等しい。
-   `!!!`と`!`は等しい。
-   `!!!!`と`!!`は等しい。

よって、プログラムの先頭から連続する`-`の数、プログラム全体の`!`の数のみから、出力すべきプログラムが定まる。

### 実装

``` python
#!/usr/bin/env python3
s = input()
minus = 0
bang = 0
for c in s:
    if c == '!':
        bang += 1
    elif c == '-' and bang == 0:
        minus += 1
minus %= 2
if bang:
    bang = 2 - bang % 2
print('-' * minus + '!' * bang)
```
