---
layout: post
date: 2019-11-03T23:59:59+09:00
tags: ["competitive", "writeup"]
---

#  早稲田大学プログラミングコンテスト2019: I - Ramen

## 考察過程

-   式は $$p_i = \min \left( x_i, \min_j \left( p_j + (d_j - d_i)^2 \right) \right)$$ である
-   $\min(x_i, \cdot)$ 成分はあまり気にしなくてよい。後ろが重要
-   $$p_j + (d_j - d_i)^2 = d_i^2 - 2 d_j d_i + p_j + d_j^2$$ は $2$ 乗なので CHT できないね
-   影響範囲を考えたい。$d_i \lt d_j \lt d_k$ とする。制約は $d_i \le p_j + (d_j - d_i)^2$ と $d_i \le p_k + (d_k - d_i)^2$ である。$k \to j$ の順でお店ができていて $p_j \le p_k + (d_k - d_j)^2$ であるか、$j \to k$ の順でお店ができていて $p_k \le p_j + (d_j - d_k)^2$ であるかで場合分け。どちらにせよ $j$ についての制約のみ考えればよい
    -   $x_j, x_k$ の要素があるから嘘だったぽい
-   三角不等式みたいな感じか
-   つまり実は常に左右のふたつのお店の値段だけを考慮すればよい

実装しました。嘘でした。$x_j$ が小さいので $p_j$ も小さいゲロマズ激安みたいなお店がすこし遠くにできた場合が問題となる。

分からないのでヒントを使用。「$p_j + (d_j - d_i)^2 = d_i^2 - 2 d_j d_i + p_j + d_j^2$ は CHT できます」それはそう。

-   つまり単に $p_i = \min(x_i, f(d_j))$ として $$f(x) = x^2 + \min \left\lbrace a x + b ~\middle|~ j,~ a = - 2 d_j,~ b = p_j + d_j^2 \right\rbrace$$ をするだけか
-   するだけではない。削除があるので
-   縦横入れ替え的なのはどうか？ $p_j$ が決定されたとき時刻 $o_i \in [o_j, c_j]$ に開店するお店のそれぞれに更新をかける。つまり貰う形から配る形にする
-   convex hull trick のデータ構造を時間方向に伸びる segment tree に乗せる感じはどうか？ マージテクをする
-   配る形はやば $2$ 次元 segtree になりそうでやだな。しかしマージテクは定数倍が厳しくないか？
-   区間だし rollback Mo's algorithm <https://snuke.hatenablog.com/entry/2016/07/01/000000> ぽいな
-   しかし snapshot に永続 CHT がほしくなってしまう。永続版 `std::set` `std::map` に差し替えるだけとはいえ、持ってないし困るな

実装ガチャつらいので解説を使用。
時間方向セグ木が正解だったが、マージテクは要らなかった。

## 解説

CHT をします。
削除が困りますが、これは各頂点に CHT を乗せた双対セグ木 (monoid を使わない) をすればよい。
$O(N (\log N)^2)$。

## メモ

-   この monoid を使わない双対セグ木、面白い
-   空間消費は $700$ MB ぐらいになった

## リンク

-   <https://atcoder.jp/contests/wupc2019/tasks/wupc2019_i>
-   実装: <https://atcoder.jp/contests/wupc2019/submissions/8265493>
