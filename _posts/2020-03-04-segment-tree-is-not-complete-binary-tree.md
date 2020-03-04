---
category: blog
layout: post
date: 2020-03-04T09:00:00+09:00
tags: [ "competitive", "segment-tree" ]
---

# セグメント木は完全二分木に限定されたデータ構造ではない


## 競プロ界隈では、「セグメント木」は完全二分木に限るものだという理解がある

競プロ界隈では「セグメント木」は完全二分木[^array]と強く結び付けられて理解されている。
現在 (2020年3月) Google で「競技プログラミング セグメント木」などと検索すると「セグメントツリーは、完全二分木の形をしている」などといった説明が多数見つかる[^tsutaj][^ei1333][^furuya]。

これは [プログラミングコンテストチャレンジブック 第2版](https://www.amazon.co.jp/dp/B00CY9256C) (通称: 蟻本) に由来するものだと思われる。蟻本は日本の競技プログラミング界隈での標準的な教科書であるが、その p153 には以下に引用したように「セグメント木は完全二分木を使う」と書かれている。

>   セグメント木は区間を扱うのが得意な、次図のようなデータ構造です。完全二分木（すべての葉の深さが等しい二分木のこと）であり、各接点は、区間を管理します。…

このような説明になっているのは、蟻本が競技プログラミングの入門書だからだろう。
競技プログラミングにおいては漸近的計算量のみならず実装量や定数倍も重要である。配列上の完全二分木を用いたセグメント木は、簡単に実装でき高速に動作するために実用上適切である。
また、入門書であるために平衡二分木の説明が省略されており、完全二分木を用いた説明しかできなかったという事情もあるだろう。実際、巻末の「本書で扱わなかった発展的トピック」の中に「平衡二分探索木」が挙げられている。


## しかし競プロ界隈以外では、セグメント木は平衡二分木を用いるデータ構造である

学術分野 (つまり、競プロ界隈以外) では、セグメント木は完全二分木には限定されたものではない。
たとえば、おそらくは有名な入門書[^famous]である [Computational Geometry: algorithms and applications](https://link.springer.com/book/10.1007/978-3-662-03427-9) の $10$ 章 MORE GEOMETRIC DATA STRUCTURESMORE においては、以下で引用したように「セグメント木の骨格は平衡二分木である」と説明されている。完全二分木には限定されていない[^origin]。

>   The skeleton of the segment tree is a balanced binary tree $\mathcal{T}$. The leaves of $\mathcal{T}$ correspond to the elementary intervals induced by the endpoints of the intervals in I in an ordered way: …


## 平衡二分木を用いたセグメント木では、より多くのことができる

列への要素の挿入クエリや削除クエリ、反転クエリとかができます。永続化もあります。赤黒木とかに乗せて適当にやってください (省略)


## 関連ツイート

分かりやすい図:

<blockquote class="twitter-tweet"><p lang="ja" dir="ltr">木で列を管理する一般的なテクです <a href="https://t.co/oQiE2Xyk6k">pic.twitter.com/oQiE2Xyk6k</a></p>&mdash; くれちー (@kuretchi) <a href="https://twitter.com/kuretchi/status/1231816561318457344?ref_src=twsrc%5Etfw">February 24, 2020</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

論文に詳しい人の発言 (上の図のツイートをリツイートした直後のツイート):

<blockquote class="twitter-tweet" data-partner="tweetdeck"><p lang="ja" dir="ltr">実は論文でセグ木というとこっちを指します（競プロと論文で用語がずれてる例の１つ）</p>&mdash; ™ 🔰 (@tmaehara) <a href="https://twitter.com/tmaehara/status/1232011335669432320?ref_src=twsrc%5Etfw">February 24, 2020</a></blockquote>
<script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

---

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

[^famous]: この分野には詳しくないけどたぶんそう

[^origin]:
    なお、セグメント木が初めて発見されたときにすでに平衡二分木を用いていたかについては確認できなかった。
    セグメント木は Jon Louis Bentley によって "Solutions to Klee's rectangle problems" (1977) で初めて発見されたそうである[^discovered]。
    しかしこれは unpublished manuscript であり、少なくとも web 上には見つからない。

[^discovered]:
    "Computational Geometry: algorithms and applications" に次のようにある。
    > The segment tree was discovered by Bentley [33].
