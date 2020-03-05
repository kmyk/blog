---
category: blog
layout: post
date: 2020-03-04T23:00:00+09:00
edited: 2020-03-05T15:00:00+09:00
tags: [ "competitive", "segment-tree" ]
---

# セグメント木は完全二分木に限定されたデータ構造ではない


## 競プロ界隈では、「セグメント木」は完全二分木に限るものだという理解がある

競技プログラミングのコミュニティでは「セグメント木」は完全二分木[^array]と強く結び付けられて理解されている。
現在 (2020年3月) Google で「競技プログラミング セグメント木」などと検索すると「セグメントツリーは、完全二分木の形をしている」などといった説明が多数見つかる[^tsutaj][^ei1333][^furuya]。

これは [プログラミングコンテストチャレンジブック 第2版](https://www.amazon.co.jp/dp/B00CY9256C) (通称: 蟻本) に由来するものだと思われる。蟻本は日本の競技プログラミング界隈での標準的な教科書であるが、その p153 には以下に引用したように「セグメント木は完全二分木を使う」と書かれている。

>   セグメント木は区間を扱うのが得意な、次図のようなデータ構造です。完全二分木（すべての葉の深さが等しい二分木のこと）であり、各接点は、区間を管理します。…

このような説明になっているのは、蟻本が競技プログラミングの入門書だからだろう。
競技プログラミングにおいては漸近的計算量のみならず実装量や定数倍も重要である。配列上の完全二分木を用いたセグメント木は、簡単に実装でき高速に動作するために実用上適切である。
また、入門書であるために平衡二分木の説明が省略されており、完全二分木を用いた説明しかできなかったという事情もあるだろう。実際、巻末の「本書で扱わなかった発展的トピック」の中に「平衡二分探索木」が挙げられている。


## しかし競プロ界隈以外では、セグメント木は平衡二分木を用いるデータ構造である

学術分野 (つまり、競プロ界隈以外) では、セグメント木は完全二分木には限定されたものではない。
少なくとも最も初期のセグメント木は完全二分木を用いていたようだが、それ以降は単に平衡二分木を用いている。

セグメント木は Jon Louis Bentley によって "Solutions to Klee's rectangle problems" (1977) で初めて発見された (これは unpublished manuscript であり、少なくとも web 上には見つからない)。
この数年後に Bentley が発表した ["An Optimal Worst Case Algorithm for Reporting Intersections of Rectangles" (1980)](https://ieeexplore.ieee.org/document/1675628) では、以下で引用したように、セグメント木は完全二分木を用いて説明されている。

>   The segment tree is based on the idea of representing a set of intervals on the line by a perfectly balanced binary tree; a line segment is then represented by "covering" it with certain nodes of the tree.

ただし、ここでの「セグメント木」は、数直線上の線分の集合を管理し以下の $3$ 種のクエリを処理するものである。ただしその線分の端点としてありえる座標は高々 $m$ 種類であって事前に固定されているとする。これは現在の競プロ界隈で「双対セグメント木」と呼ばれるものに近い。

1.  追加: 与えられた線分を集合へ追加する。計算量は $O(\log m)$。
2.  削除: 与えられた線分を集合から削除する。計算量は $O(\log m)$。
3.  報告: 与えられた点と交点を持つような線分をすべて報告する。計算量は報告する線分が $k$ 本のとき $O(\log m + k)$。

[Computational Geometry: algorithms and applications](https://link.springer.com/book/10.1007/978-3-662-03427-9) の $10$ 章 MORE GEOMETRIC DATA STRUCTURESMORE は、セグメント木の説明に平衡二分木を用いている。
これは有名な教科書であるようであり、その説明はおそらくセグメント木についての標準的なものと思ってよいだろう。
セグメント木は Bentley によって発見された線分の集合を管理するデータ構造であるとしながら、以下で引用したように「セグメント木の骨格は平衡二分木である」と書かれている。ここでは完全二分木には限定されていない。

>   The skeleton of the segment tree is a balanced binary tree $\mathcal{T}$. The leaves of $\mathcal{T}$ correspond to the elementary intervals induced by the endpoints of the intervals in I in an ordered way: …

ここで気になるのが Bentley のセグメント木と競プロ界隈のセグメント木の関係である。
Bentley のセグメント木は線分を高速に列挙するためのものであり、我々のセグメント木はモノイドの積を高速に計算するためのものであるが、これらに関係はあるだろうか？
Bernard Chazelle は ["A functional approach to data structures and its use in multidimensional searching" (1988)](https://epubs.siam.org/doi/abs/10.1137/0217026) の中で Bentley のセグメント木を参照しながら、たとえば次ができるようなデータ構造を提案している: 点集合 $V$ および点から可換半群 $(G, +)$ の要素への関数 $v : V \to G$ が固定されているとして、このとき与えられた区間 $q$ に対し $\sum _ {p \in V \cap q} v(p)$ を $O(\log n)$ で答える。
これは我々の知るセグメント木とほぼ変わらないデータ構造である。
よって Bentley のセグメント木、Chazelle のデータ構造、我々の知るセグメント木には関係があると言える。
そしてもちろん Chazelle のデータ構造も限定された定義にはなっていない。


## 平衡二分木を用いたセグメント木では、より多くのことができる

列への要素の挿入クエリや削除クエリ、反転クエリとかができます。永続化もあります。赤黒木とかに乗せて適当にやってください (省略)


## 関連ツイート

分かりやすい図:

<blockquote class="twitter-tweet"><p lang="ja" dir="ltr">木で列を管理する一般的なテクです <a href="https://t.co/oQiE2Xyk6k">pic.twitter.com/oQiE2Xyk6k</a></p>&mdash; くれちー (@kuretchi) <a href="https://twitter.com/kuretchi/status/1231816561318457344?ref_src=twsrc%5Etfw">February 24, 2020</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

論文に詳しい人の発言 (上の図のツイートをリツイートした直後のツイート):

<blockquote class="twitter-tweet" data-partner="tweetdeck"><p lang="ja" dir="ltr">実は論文でセグ木というとこっちを指します（競プロと論文で用語がずれてる例の１つ）</p>&mdash; ™ 🔰 (@tmaehara) <a href="https://twitter.com/tmaehara/status/1232011335669432320?ref_src=twsrc%5Etfw">February 24, 2020</a></blockquote>
<script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

---

-   Thu Mar  5 14:34:17 JST 2020
    -   Bentley のセグメント木がよく見たら完全二分木だったので修正 <https://twitter.com/noshi91/status/1235341921360515074>

[^array]: 特に、特定の順序で添字付けて配列に格納するもの

[^furuya]:
    >   「セグメントツリーは、完全二分木の形をしている」

    [セグメントツリー入門 - クリエイティヴなブログ](https://www.creativ.xyz/segment-tree-entrance-999/)

[^tsutaj]:
    >   セグメント木は皆さんご存知のとおり、図で書くとこんな形をしています。… 元のデータ数以上になる最小の 2 冪の数を N とします。すると、ノードは全部で 2N−1 個あります。

    [セグメント木をソラで書きたいあなたに - hogecoder](http://tsutaj.hatenablog.com/entry/2017/03/29/204841)

[^ei1333]:
    >   完全二分木である。モノイドに対する区間への様々な演算が $O(\log N)$ で実現できる。

    [セグメント木(Segment-Tree) \| Luzhiled’s memo](https://ei1333.github.io/luzhiled/snippets/structure/segment-tree.html)
