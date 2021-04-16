---
category: blog
layout: post
date: 2021-04-17T00:00:00+09:00
---

# 行や列に対応する頂点を作る一般的なテク

## 概要

$H \times W$ のグリッドのマス目のそれぞれを頂点としてグラフを考えるとき、行や列に対応する $H + W$ 個の頂点からなる二部グラフを考えるとうまくいくことがあります。


## 説明

$H \times W$ のグリッドに対し、行や列に対応する $H + W$ 個の頂点を考え、グリッドのマスのうち注目しているもののそれぞれを辺とします。
つまり、マス $(x, y)$ を列 $x$ と行 $y$ との間の辺 $(x, y)$ とみなします。
グラフは $H + W$ 個の頂点と高々 $H W$ 個の辺を持つものになります。
このグラフは行に対応する頂点の集合と列に対応する頂点の集合からなる二部グラフです。

たとえば $H = 4$ かつ $W = 5$ のグリッド上で $K = 5$ 個の頂点 $(0, 0), (1, 3), (2, 1), (3, 2), (4, 1)$ に注目する場合を考えてみましょう (図1)。
この場合には対応する二部グラフは $H + W = 9$ 頂点かつ $K = 5$ 辺のグラフになります (図2)。

<figure>
<img src="/assets/img/row-column-vertices-grid.svg">
<figcaption>図1. グリッド</figcaption>
</figure>

<figure>
<img src="/assets/img/row-column-vertices-graph.svg">
<figcaption>図2. 二部グラフ</figcaption>
</figure>


## 例題

-   [AtCoder Regular Contest 045: D - みんな仲良し高橋君](https://atcoder.jp/contests/arc045/tasks/arc045_d)
-   [AtCoder Regular Contest 112: D - Skate](https://atcoder.jp/contests/arc112/tasks/arc112_d)
-   [Codeforces Round #500 (Div. 1) [based on EJOI] B. Chemical table](https://codeforces.com/contest/1012/problem/B)
-   [Kyoto University Programming Contest 2017: J - Paint Red and Make Graph](https://atcoder.jp/contests/kupc2017/tasks/kupc2017_j)
-   [No.1479 Matrix Eraser - yukicoder](https://yukicoder.me/problems/no/1479)


## その他

-   このような構成や変換にすでになにか良い名前が付けられていれば教えてください。
-   元々のグリッドは、マスを頂点としかつ行や列を共有しているマスの間に辺を張って $H W$ 頂点 $W {} _ 2 C _H + H {} _ 2 C _ W$ 辺のグラフと見ることができます。このとき、グリッドと二部グラフとの間の変換は、なんらかの意味での辺と頂点との入れ替えだと見ることができます[^noimi]。
-   行に対応する頂点と列に対応する頂点との間に辺を張るのでなく、行や列に対応する頂点と元々のグリッドのマスに対応する頂点との間に辺を張って $H W + H + W$ 頂点 $2 H W$ 辺の二部グラフを考えることもできます。


## 注釈

[^noimi]: <https://twitter.com/noimi_kyopro/status/1383118229782949890><sup>[archive.org](https://web.archive.org/web/20210416192742/https://twitter.com/noimi_kyopro/status/1383118229782949890)</sup>
