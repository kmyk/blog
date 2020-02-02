---
category: blog
layout: post
date: "2017-12-03T23:59:59+09:00"
title: "matroid上の貪欲法が最適解を得ることの証明"
tags: [ "competitive", "greedy", "matroid" ]
---

matroidは競プロで貪欲法をしていると背後に現れていることで有名。
貪欲ができないのはこれをちゃんと理解していないからかなと思ったので調べ、ほしい部分に証明がなかったので書いた。
自分用に書いたがついでに公開しておく。

## 定義 1

有限集合 $E$ とその部分集合族 $\mathcal{I} \subseteq \mathcal{P}(E)$ の対 $\mathbf{M} = (E, \mathcal{I})$ がmatroidであるとは、以下の$3$つを満たすこと。

1.  非空: $\emptyset \in \mathcal{I}$
2.  下に閉: $\forall Y \in \mathcal{I}. \forall X \subseteq Y. X \in \mathcal{I}$
3.  増加公理: $\forall X, Y \in \mathcal{I}. \|X\| \lt \|Y\| \to \exists y \in Y \setminus X. X \cup \\{ y \\} \in \mathcal{I}$

さらに

-   部分集合 $X \in \mathcal{I}$ は $\mathbf{M}$ の独立集合と呼ぶ。
-   (包含関係の意味での)極大独立集合を基と呼ぶ。
-   $\mathbf{M}$ の極大独立集合の全体の集合を $\mathbf{M}$ の基族 $\mathcal{B}$ と呼ぶ。
-   基の要素数は全て等しい(増加公理から明らか)ので、これを $\mathbf{M}$ のrankと呼び $\mathrm{rank}(\mathbf{M})$ と書く。

## 定義 2

-   matroid $\mathbf{M} = (E, \mathcal{I})$ に対する重み $w$ とは、関数 $w : E \to \mathbb{R}$。(非負性などは要求してないことに注意。)
-   $X \in \mathcal{I}$ に対し $w(X) = \sum\_{x \in X} w(x)$ と定義し、独立集合への拡張とする。
-   matroid $\mathbf{M}$ の重み $w$ に関する重み最大化問題の解とは、$w(X) = \max \\{ w(Y) \mid Y \in \mathcal{B} \\}$ を満たす $X \in \mathcal{B}$。
    独立集合でなく基であることに注意。

貪欲法とは次のアルゴリズム。基をひとつ定める。

1.  $X \gets \emptyset$
2.  for $x \in E$, order by $w(x)$ desc:
    1.  if $X \cup \\{ x \\} \in \mathcal{I}$:
        1.  $X \gets X \cup \\{ x \\}$
3.  print $X$

## 定義 3

matroid $\mathbf{M} = (E, \mathcal{I})$ の非負整数 $k \le \mathrm{rank}(\mathbf{M})$ による打ち切りとは、$\mathcal{I}^{(k)} = \\{ X \in \mathcal{I} \mid \|X\| \le k \\}$ により得られるmatroid $\mathbf{M}^{(k)} = (E, \mathcal{I}^{(k)})$。

$k = \mathrm{rank}(M)$ なら $\mathbf{M}^{(k)} = \mathbf{M}$ であることに注意。


## 定理 4

任意のmatroid $\mathbf{M}$ と重み $w$ に対し、貪欲法によって得られる基は重み最大化問題の解。

### 証明

$r = \mathrm{rank}(\mathbf{M})$ とする。
独立集合が下に閉であることを使えば、貪欲法は次のような構成とみなしてよい:

-   $X\_0 = \emptyset$
-   $X\_{i + 1} = X\_i \cup \\{ x\_i \\}$ for $i + 1 \le r$
    -   ただし $x\_i$ は $w(x\_i) = \max \\{ w(y) \mid X \subsetneq X \cup \{ y \} \in \mathcal{I} \\}$ を満たす

$X = X\_r$ が出力である。

このとき次の補題を示せば定理が示されたことになる。
補題: 全ての $i \le r$ に対し、$X\_i$ はmatroid $\mathbf{M}^{(k)}$ に関する重み最大化問題の解。

これは$i$に関する帰納法で示す。

-   $i = 0$ のとき: 明らか。
-   $i$ での成立を仮定し $i + 1$ について: 背理法。$w(X\_{i + 1}) \lt w(Y)$ な $Y \in \mathcal{B}^{(i + 1)}$ の存在を仮定する。
    $y \in \mathrm{argmin}\_{x \in Y \setminus X\_i} w(x)$ をとる ($\mathrm{argmax}, X\_{i+1}$ ではないことに注意)。
    -   $w(x\_i) \ge w(y)$ のとき: $Y' = Y \setminus \\{ y \\}$ とする。下に閉より $Y' \in \mathcal{I}$ つまり $Y' \in \mathcal{B}^{(i)}$。$w(X\_i) = w(X\_{i + 1}) - w(x\_i) \lt w(Y) - w(y) = w(Y')$ となるが、これは帰納法の仮定に矛盾。
    -   $w(x\_i) \lt w(y)$ のとき: 増加公理より $z \in Y \setminus X\_i$ で $X\_i \cup \\{ z \\} \in \mathcal{I}$ なものがある。$y$ の取り方より $w(y) \le w(z)$。$w(X\_{i + 1}) \lt w(X\_i \cup \\{ z \\})$ となるが、これは $X\_{i + 1}$ の構成に矛盾。

$\Box$

## 系 5

貪欲法の過程ででてくる $X$ すべての中で重みが最大の独立集合を $X' \in \mathcal{I}$ とすれば、$w(X') = \max \\{ w(Y) \mid Y \in \mathcal{I} \\}$ を満たす。
