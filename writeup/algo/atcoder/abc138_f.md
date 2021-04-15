---
redirect_from:
layout: post
date: 2019-08-21T23:59:59+09:00
tags: ["competitive", "writeup"]
---

# AtCoder Beginner Contest 138: F - Coincidence

## 問題

与えられた正整数 $L, R$ に対し、次を満たす組 $(x, y)$ の数を数えよ:

-   $L \le x \le y \le R$
-   $y \bmod x = y \oplus x$

## 解説

式変形して $2$ 進数の桁 DP。$O(\log R)$。

式変形をすると $\mathrm{msb}(L) \le \mathrm{msb}(x) = \mathrm{msb}(y) \le \mathrm{msb}(R)$ であって bit の集合として $x \subseteq y$ な組 $(x, y)$ を数えればよいことが分かる。
これは普通の桁 DP で求まる。
$R$ の $2$ 進数への変換ができているとして、計算量は $O(\log R)$ でできる。
最上位 bit ごとに個別に数えて $O((\log R)^2)$ でも間に合う。

## 考察

-   えっ 分からない
-   $f(L, R + 1) = f'(R + 1) - f'(L)$ にするやつしたい
-   無理そう ($x \lt L \le y \le R$ な組がありうるので)
-   $y \bmod x \lt x \le y$ が成り立つ
-   一般に $y \oplus x = y + x - 2 (y \& x)$
-   $x = (10000) _ 2$ を考えると $y$ は $(10000) _ 2$ から $(11111) _ 2$ まですべて
-   実験すると $x \subseteq y$ が見える

    ``` python
    >>> print(*(lambda y: map(bin, filter(lambda x: y % x == y ^ x, range(1, y + 1))))(0b10010))
    0b10000 0b10010
    >>> print(*(lambda y: map(bin, filter(lambda x: y % x == y ^ x, range(1, y + 1))))(0b10011))
    0b10000 0b10001 0b10010 0b10011
    >>> print(*(lambda y: map(bin, filter(lambda x: y % x == y ^ x, range(1, y + 1))))(0b11110))
    0b10000 0b10010 0b10100 0b10110 0b11000 0b11010 0b11100 0b11110
    ```
    
-   剰余と排他的論理和の性質から $x, y$ の最上位 bit は同じであることが言える
-   $x, y$ の最上位 bit は同じの仮定を加えた下で $y \bmod x = y - x$
-   よって $y - x = y + x - 2 (y \& x)$ となり整理すると $y \& x = x$ つまり (bit の集合として) $x \subseteq y$
-   桁 DP したい
-   しかし桁 DP なら制約が $L, R \le 10^{18}$ にはならないのでは？
-   $O(\log R)$ 支払って最上位 bit の位置を固定するのがよさそう
-   $\mathrm{msb}(L) \le \mathrm{msb}(x) = \mathrm{msb}(y) \le \mathrm{msb}(R)$ である
-   $\mathrm{msb}(L) \lt \mathrm{msb}(x) = \mathrm{msb}(y) \lt \mathrm{msb}(R)$ な組 $(x, y)$ は $L, R$ を気にしなくてよい
-   $L, R$ を気にしなくてよい $k = \mathrm{msb}(x) = \mathrm{msb}(y)$ な組は $k$ 未満の位置の bit それぞれについて $3$ 通りなので $3^k$ 個
-   やっぱり桁 DP しないとだめそう
-   普通に桁 DP だった


## リンク

-   <https://atcoder.jp/contests/abc138/tasks/abc138_f>
-   <https://atcoder.jp/contests/abc138/submissions/7063785>
