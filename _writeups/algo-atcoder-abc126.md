---
redirect_from:
  - /writeup/algo/atcoder/abc126/
layout: post
date: 2019-10-21T23:59:59+09:00
tags: ["competitive", "writeup"]
---

# AtCoder Beginner Contest 126

## A - Changing a Character

はい

## B - YYMM or MMYY

はい

## C - Dice and Coin

愚直に計算して $O(N \log N)$ でよい。$O(N)$ にもできます

## D - Even Relation

適当な根からの深さの偶奇に従って塗ればよい。 $O(N)$

## E - 1 or 2

$X_i, Y_i, Z_i$ の値と事実「$A _ {X_i} + A _ {Y_i} + Z_i$ は偶数である」が分かっている $\iff$ $A _ {X_i}$ の偶奇が分かれば $A _ {Y_i}$ の偶奇が分かり、かつその逆もそう。$O(N)$ あるいは $O(N \alpha(N))$

## F - XOR Matching

自明な構成 $a = (\dots, 2, 1, 0, K, 0, 1, 2, \dots, K)$ が可能かどうかだけ見ればよい。実質 $O(1)$ だが出力に $O(N)$。
$(M, K) = (0, 0)$ と $(M, K) = (1, 0)$ がコーナーぽい ($1$ 敗)

証明: $M \ge 2$ のとき $0 \oplus 1 \oplus \dots 2^M - 1 = 0$ であるので $0 \oplus 1 \oplus \dots \oplus K - 1 \oplus K + 1 \oplus \dots \oplus 2^M - 1 = K$ である。よって自明な構成が常に可能。

## メモ

-   F はちょっと困った ($20$ 分) が、未証明でえいっした
-   証明自明じゃん。先に解説を見てしまったが、まじめに証明しようとするとすぐできてただろうなって感じの自明さ
-   $6$ 問の ABC はもうちょっと難しいと思っていたがそうではなかった。この回は初回だから傾向が違うのかな？

## 追加

-   D がある固定された $K$ に対し「同じ色に塗られた任意の  $2$ 頂点について、その距離 $d$ が $d \equiv 0 \pmod{K}$ である」だった場合はどうなるか？ $2$ 色での塗り分けが不可能だとすれば、塗り分けに必要な色の数の最小値は求まるか？
    -   $K$ 色で塗っていい場合はまったく同じ議論が使えて自明になる
    -   なお $2$ 色しか使えない場合は、不可能なものが自明に存在する。可能性判定が必要であるが、$d(a, b) \equiv d(a, c) \equiv 0 \pmod{K}$ が $d(b, c) \equiv 0 \pmod{K}$ を含意しないので面倒そう。それでも貪欲でいける気がする
-   E がある固定された $K$ に対し「各カードには整数  $1, 2, \dots, K$ のいずれかが書かれています」「$A _ {X_i} + A _ {Y_i} + Z_i \equiv 0 \pmod{K}$ である」だった場合はどうなるか？
    -   これは自明。まったく同じ議論が使えるため
-   F が「構成せよ」でなく「個数を数えよ」だった場合はどうなるか？ 最低でも $2 \cdot (2^M - 1)!$ あるのは分かるが、それ以上はあるか？
    -   分からない

## リンク

-   <https://atcoder.jp/contests/abc126>
-   F の提出: <https://atcoder.jp/contests/abc126/submissions/8069764>
