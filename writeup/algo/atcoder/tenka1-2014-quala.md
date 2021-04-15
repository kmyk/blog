---
redirect_from:
  - /writeup/algo/atcoder/tenka1-2014-quala/
layout: post
date: 2019-11-20T23:59:59+09:00
tags: ["competitive", "writeup"]
---

# 天下一プログラマーコンテスト2014予選A

## C - 天下一文字列集合

制約が bit DP って言ってるので bit DP をします。
ただし $m$ が大きいときに $O(2^nm)$ は間に合わない。
さてパターンの集合 $\mathbf{P} = \lbrace P _ {i_0}, P _ {i_1}, \dots, P _ {i _ {k - 1}} \rbrace$ をひとつの文字列 $s$ にまとめられることを $\varphi(\mathbf{P})$ と書くことにすると、これは $\mathbf{P}$ 中の任意の $2$ 要素がひとつの文字列にまとめられることに等しい、つまり $\varphi(\mathbf{P}) ~\leftrightarrow~ \forall a, b \in \mathbf{P}.~ \varphi(\lbrace a, b \rbrace)$ が成り立つ。
これを使うと $O(n^2m + 3^n)$ になる。

## E - パズルの移動

強連結成分分解していい感じの代数構造で zeta 変換。$O(HW + Q)$。

とりあえずピース間の干渉関係を有向グラフにしておく。
するとこの有向グラフの葉を順番に切っていきながら動くブロックの数を数える DP をしたくなるが、DAG とは限らないので不可能で、もし強連結成分分解したとしても合流があるのでまだだめで、一般の poset に対する zeta 変換は計算量が指数になりそう。
これはブロックの個数の加算に羃等性がないのが原因である。

そこで DP の下部の代数構造を $(\mathbb{N}, +)$ から $(\mathbb{N}^W, \max)$ に変更する。
ただしこの $\max$ は pointwise なもので、つまり各列の高さを記録するものである。
これはつまり「演算に羃等性を持たせることで一般の poset の zeta 変換を求めることができる」という事実を用いている。
この演算で zeta 変換のようにした後、動く面積 $a = \sum _ {x \le W} h_x$ として答えが求まる。

## メモ

-   D は幾何で面倒なだけぽいのでパス

## リンク

-   <https://atcoder.jp/contests/tenka1-2014-quala/tasks/tenka1_2014_qualA_c>
-   C 提出: <https://atcoder.jp/contests/tenka1-2014-quala/submissions/8534290>
-   E 提出: <https://atcoder.jp/contests/tenka1-2014-quala/submissions/8536205>
