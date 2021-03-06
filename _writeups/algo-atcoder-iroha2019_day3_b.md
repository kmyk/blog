---
redirect_from:
  - /writeup/algo/atcoder/iroha2019_day3_b/
layout: post
date: 2019-05-24T23:59:59+09:00
tags: ["competitive", "writeup"]
---

# いろはちゃんコンテスト Day3: B - ゐろはちゃん

## 考察

(解説を見た)

## 解法

最初の質問に使わなかった頂点の $3$ つ組をすべて試して、頻度を見るあるいは関連する頂点の数を見る。

<hr>

頂点の組 $(x, y, z)$ に対する質問の結果を $q(x, y, z)$ と書くとする。
ある頂点の組の集合 $A$ に対し、そのすべてについて質問した結果の頻度 $R(A) = \# \{ a \in A \mid q(a) = \mathrm{Rectangle} \}$ および $S(A), T(A)$ を求めておく。
正しい場合の頻度 $(r, s, t)$ が分かっていて、どれかが過半数 ($r \gt s + t$ など) である場合、偽物はこれを再現できない。

最初の質問はどのように行なっても (番号の置換を除いて) まったく同じであるので $q(0, 1, 2)$ としてよい。
さてこれが `Square` あるいは `Rectangle` なら、$0, 1, 2$ 以外の頂点 $3, 4, 5, 6, 7$ の $3$ つ組のすべて (計 $10$ 個) について質問すればよい。それぞれ `Square`, `Rectangle` の頻度が過半数の $6$ でなければならないため。

問題は最初の質問で `Triangle` が得られた場合。
$(r, s, t) = (3, 3, 4)$ であるのでこれでは区別できない。
さて `Triangle` を返す質問に関連する頂点の個数 $\# \{ x \ge 2 \mid \exists y \gt x. \exists  z \gt y. ~ q(x, y, z) = \mathrm{Triangle} \}$ を考える。
これは本物なら $4$ でなければならないが、偽物はこれを $4$ にできない。


## メモ

-   添字が不確定の場合は「すべてを試す」とすると添字に依存しないので上手くいく
-   いったん「頻度」として取り出すと容易な場合の処理が楽

## リンク

-   <https://atcoder.jp/contests/iroha2019-day3/tasks/iroha2019_day3_b>
-   <https://atcoder.jp/contests/iroha2019-day3/submissions/5559624>
