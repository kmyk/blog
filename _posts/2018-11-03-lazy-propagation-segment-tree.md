---
category: blog
layout: post
date: "2018-11-03T05:43:25+09:00"
edited: "2018-12-06T00:00:00+09:00"
tags: [ "competitive", "segment-tree", "lazy-propagation", "range-extension", "partiality-extension", "total-function", "coordinate-compression", "monoid", "operator-monoid" ]
---

# 遅延伝搬segment木についてもっと詳しく

## 概要

私の中で遅延伝搬segment木に関する理解が進んだため、これを記録しておくため書かれた。
特に以下の3種のテクについて解説する。

-   二分探索の融合: segment木上の二分探索は $$O((\log n)^2)$$ から $$O(\log n)$$ に落とせる
-   区間拡張: 区間monoidとの直積monoidを考えると座標圧縮の場合などで便利
-   部分性拡張: 作用素monoidの全域性を捨てることで扱える操作が存在する

## 復習

$$M$$ を[monoid](https://ja.wikipedia.org/wiki/%E3%83%A2%E3%83%8E%E3%82%A4%E3%83%89)とする。
segment-treeとは、 $$M$$ の要素の列 $$(a_0, a_1, \dots, a _ {n-1})$$ に関して、要素のそれぞれを葉とする完全二分木を用いて次をすべて $$O(\log n)$$ で処理するデータ構造。

-   点更新: 与えられた $$i \lt n$$ と $$b \in M$$ に対し、 列の $$a_i \gets b$$ という更新を行う
-   区間和: 与えられた $$0 \le l \le r \le n$$ に対し、 $$a_l \cdot a _ {l + 1} \cdot \dots \cdot a _ {r - 1}$$ を求める

ただし $$M$$ が単位元を持つことはあまり本質的ではなく、結合律が重要である。なお半群からは自動的にmonoidを生成できる。

$$M$$ をmonoidとし、 $$F$$ を作用素monoidとする。
つまり次を満たす:

-   $$F$$ はmonoid
-   演算 $$\star : F \times M \to M$$ がある。ただし $$f \star a$$ を $$f(a)$$ と略記する
-   $$\star$$ は第1引数を固定したとき $$M$$ 準同型、つまり $$f(e) = e$$ かつ $$f(a \cdot b) = f(a) \cdot f(b)$$
-   $$\star$$ は $$\cdot_M$$ と分配的、つまり $$f(a \cdot b) = f(a) \cdot f(b)$$
-   $$\star$$ は $$\cdot_F$$ と結合的、つまり $$(g \cdot f)(a) = g(f(a))$$

このときlazy-propagation segment-treeとは、 $$M$$ の要素の列 $$(a_0, a_1, \dots, a _ {n-1})$$ に関して、要素のそれぞれを葉とする完全二分木を用いて次をすべて $$O(\log n)$$ で処理するデータ構造。

-   点更新
-   区間和
-   区間更新: 与えられた $$0 \le l \le r \le n$$ と $$f \in F$$ に対し、 $$i \in [l, r)$$ のぞれぞれについて、 $$a_i \gets f(a_i)$$ という更新を行う

## 二分探索の融合

$$M$$ 上に全順序 $$\le \subseteq M \times M$$ が定まっているとする。
通常あるいは遅延伝播のsegment木の上で、次の操作を考える:

-   下限取得: 与えられた $l \lt n$ と $$b \in M$$ に対し、 $$\min \left\{ r \mid l \le r \le N \land b \le a_l \cdot a _ {l + 1} \cdot \dots \cdot a _ {r - 1} \right\}$$ を求める

これは単純には区間和操作を $$O(\log n)$$ 回呼びだす二分探索によって $$O((\log n)^2)$$ で計算できるが、segment木の構造に沿って二分探索をすることにより $$O(\log n)$$ で求まる。

## 区間拡張

作用演算 $$\star : F \times M \to M$$ を拡張し、segment木の頂点の対応する区間 $$[l, r)$$ を加えた $$\star^+ : F \times M \times (\mathbb{Z} \times \mathbb{Z}) \to M$$ という形で書きたい場合は多い。
これは作用の枠組みを拡張しなくても monoid $$M$$ と区間monoid $$\mathfrak{I}$$ の直積monoid $$M \times \mathfrak{I}$$ を用いれば表現できる。

例としては次のような問題がある:

>   整数列 $$(a_0, a_1, \dots, a _ {N - 1})$$ があり、始めはすべて $$0$$ である。次の $$2$$ 種のクエリが合計で $$Q$$ 個与えられるのですべて処理せよ。ただし $$Q$$ は比較的小さく (例: $$Q \approx 10^6$$)、 $$N$$ は十分大きい (例: $$N \approx 10^{12}$$) とする。
>
>   -   与えられた $$0 \le l \lt r \le N$$ と$$1$$次関数 $$f = \lambda x. ax + b$$ に対し、 $$i \in [l, r)$$ のぞれぞれについて、 $$a_i \gets f(a_i)$$ という更新を行う
>   -   与えられた $$0 \le l \lt r \le N$$ に対し、 $$a_l + a _ {l + 1} + \dots + a _ {r - 1}$$ を求める

これは今まで述べてきた枠組みのままで $$(Q \log Q)$$ で解ける。

monoid $$M$$ の要素は、区間 $$[l, r)$$ とその中の要素の総和 $$s$$ の対 $$(l, r, s)$$ とし、演算は順序に注意しながら $$(l_1, r_1, s_1) \cdot (l_2, r_2, s_2) = (l_1, r_2, s_1 + s_2)$$ とする。このままだと半群なので単位元は適当に足す。
作用素monoidの台 $$F$$ は$$1$$次関数全体の集合とする。
作用 $$f \star (l, r, s) = (l, r, as + (r - l)b)$$ ただし $$f = \lambda x. ax + b$$ と定義する。
後は事前に座標圧縮を行いそれに沿って操作を適用していけばよい。
これで $$O(Q \log Q)$$ で解けた。

これはつまり区間半群 $$\mathfrak{I} = \mathbb{Z} \times \mathbb{Z}$$ をから導出されるmonoidとの直積を考えていることに等しい。
ただし区間半群とは演算 $$[l_1, r_1) \cdot [l_2, r_2) = [l_1, r_2)$$ で定義される半群。
なお区間と呼んではいるが、ここで $$r_1 = l_2$$ や $$l_1 \le r_2$$ とは限らないことに注意。
同様の拡張により、区間でなくて単に添字の情報を乗せることもできる。

追記: 区間の構造は単に圏として整理すべきぽい (https://kimiyuki.net/blog/2018/12/06/categories-on-segment-tree/)

## 部分性拡張

作用演算 $$\star : F \times M \to M$$ は[total](http://mathworld.wolfram.com/TotalFunction.html)である必要はなく、[partial](https://ja.wikipedia.org/wiki/%E9%83%A8%E5%88%86%E5%86%99%E5%83%8F)なものを許すことで解けるようになる問題が存在する。
つまり「遅延伝搬segment木はmonoidと作用素monoidで $$\dots$$」という説明は(健全かつ実用的ではあるとしても)完全ではない。

例題を通して説明する。
次の問題を考えよう。

>   自然数列 $$(a_0, a_1, \dots, a _ {N - 1})$$ があり、始めはすべて $$0$$ である。次の $$3$$ 種のクエリが合計で $$Q$$ 個与えられるのですべて処理せよ。
>
>   -   与えられた $$0 \le l \lt r \le N$$ と $$f \in \mathbb{Z}$$ に対し、 $$i \in [l, r)$$ のぞれぞれについて、 $$a_i \gets a_i + f$$ という更新を行う。ただし要素 $$a_i$$ が負になるような入力はないとする
>   -   与えられた $$0 \le l \lt r \le N$$ に対し、 $$a_i \ge 1$$ であるような $$i \in [l, r)$$ の数を数える

これは全域性の仮定を捨てることで $$O(Q \log N)$$ で解ける。

monoid $$M$$ の要素は、区間 $$[l, r)$$ とその中の要素の最小値 $$m$$ と非零要素の数 $$c$$ の対 $$(l, r, m, c)$$ とする。
作用素monoidの台 $$F = \mathbb{Z}$$ とおく。
作用 $$f \star (l, r, m, c) = \begin{cases}
    (r, r, m , c) & (f = 0) \\
    (r, r, m + f, r - l) & (f \ne 0 \land m + f \ge 1) \\
    (l, r, 0, 0) & (f \ne 0 \land m + f = 0 \land r - l = 1) \\
    \text{未定義} & (\text{otherwise})
\end{cases}$$ と定める。
区間中の要素の最小値が $$1$$ 以上ならその区間の要素がすべて $$1$$ で合計 $$r - l$$ 個あるのは明らか。
そして区間中の要素の最小値が減少し $$0$$ になったなら情報が足りておらず答えられない。
しかしsegment木の側に手を入れ、「未定義」が返ってきたら木のその頂点への作用素 $$f$$ を左右の子へ伝播させるようにすれば、親の頂点では $$f = 0$$ となって値が定義される。
葉まで追い込めば $$r - l = 1$$ となり値を持つため計算は全体としては妥当である。
状況から再帰的に未定義が発生することはないことが言え、未定義の出現は高々 $$O(\log n)$$ 回であるのでこれによる計算量の悪化はない。
よって $$O(Q \log N)$$ で解けた。

これと同様の処理は作用素monoidの非可換性への対処として既に多く行われている。

計算が可能であることの条件は「葉に関してはすべて定義されている」であり、これが必要十分である。
計算量が $$O(\log n)$$ となる詳しい条件は未知である。
例えば葉以外ではすべて未定義の場合など、一般には計算量は $$O(n)$$ になりえるのでこの問いは重要である。
「未定義が再帰的に発生することはない」がひとつの有用な十分条件であり、上の例はこれを満たしている。

メモ:

-   例題: [HDU - 1542: Atlantis](http://acm.hdu.edu.cn/showproblem.php?pid=1542) ([vjudge](https://cn.vjudge.net/problem/HDU-1542))
-   このテクは jasonsun0310 さんとの議論の中で見付かった: [issues/3](https://github.com/kmyk/competitive-programming-library/issues/3)

## メモ

-   「遅延評価」や "lazy-evaluation" という語はできれば避けた方がよい。関数型プログラミング言語などでの用語と衝突するため
-   テクの名前はこれを書いている際に勝手に名付けた
-   遅延伝搬でないsegment木は非再帰にすると定数倍速い。可換性を仮定しない場合は結合の向きに注意。遅延伝搬ありでもできるだろうが少し面倒
-   作用素monoid $$F$$ が可換なら定数倍速くできる
