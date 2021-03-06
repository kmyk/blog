---
redirect_from:
  - /writeup/algo/atcoder/keyence2020_e/
layout: post
date: 2020-01-18T23:59:59+09:00
tags: ["competitive", "writeup"]
---

# キーエンス プログラミング コンテスト 2020: E - Bichromization

## 解法

貪欲。$D_v = D_u$ が最小値を取るような $(v, u) \in E$ から始めて葉を伸ばしていくような感じで $D_v$ の小さい順に決めていく。$O(N \log N + M)$ ぐらい。

証明:

1.  辺は自由に削除できる
    -   $C_e = 10^9$ とすればよい
1.  もし構築が可能なら (辺を適切に削除した結果として) 木の形での構築が可能である
    -   とりあえず構築して (辺の削除を戻してから) 最小全域木を取ればよい
1.  途中まで木 $T$ を構築でき、その木の大きさは $2$ 以上 ($\vert T \vert \ge 2$) であるとする。$T$ との間に辺を持つ未決定の頂点 $v$ ($\exists u \in T.~ (u, v) \in E$) は、もし木 $T$ に含まれる頂点のすべてより $D_v$ が大きい ($\forall u \in T.~ D_u \le D_v$) なら葉として付け加えることできる
    -   これにはある $u \in T$ との間の辺 $e = (u, v) \in E$ を選んで $C_e = D_v$ かつ $\mathrm{color} _ v \ne \mathrm{color} _ u$ とすればよい
1.  $D_v = D_u$ が最小値を取るような $(v, u) \in E$ を集めてきてそれらを根とし森を作り、ここから貪欲に構築をすればよい。この方法で構築できないならどんな方法でも構築できない
    -   次を確認すればよい: 頂点 $v$ であって周囲のすべて頂点よりも $D_v$ が小さい ($\forall u \in V.~ (v, u) \in E \to D_v \lt D_u$) ものがあるなら、構築が不可能である。これは明らか

## メモ

-   本番は未証明で AC
-   古い ARC あたりで似た雰囲気の問題を見た記憶があるが、問題名は不明

## リンク

-   <https://atcoder.jp/contests/keyence2020/tasks/keyence2020_e>
-   提出: <https://atcoder.jp/contests/keyence2020/submissions/9581413>
