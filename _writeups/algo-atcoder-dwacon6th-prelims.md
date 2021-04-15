---
redirect_from:
  - /writeup/algo/atcoder/dwacon6th-prelims/
layout: post
date: 2020-01-11T23:59:59+09:00
tags: ["competitive", "writeup"]
---

# AtCoder: 第6回 ドワンゴからの挑戦状 予選

## A - Falling Asleep

はい

## B - Fusing Slimes

求めたいのは $\sum _ {\sigma \in \mathfrak{S}} \sum _ {i \lt n - 1} (x _ {\mathrm{right}(\sigma, i)} - x _ {\sigma(i)})$ みたいな雰囲気の式である。
これを $\sigma \in \mathfrak{S}$ ではないものを最外にする形に変形したい。
候補としては (1.) 隣接区間 (それぞれの $i$ に対し $\sum x _ {i + 1} - x_i$), (2.) 移動 (それぞれの $l, r$ の組に対し $x_r - x_l$), (3.) $i$ 番目 (それぞれの $i$ に対し $x _ {\mathrm{right}(\sigma, i)} - x _ {\sigma(i)})$) などが思い付く。
さてガチャだが、最もそれっぽい (2.) を選べば $O(n^2)$ の解が得られる。
つまり $\sum _ l \sum _r \sum _ {\sigma \in \mathfrak{S} \wedge \phi(l, r, \sigma)} (x_r - x_l)$ (ただし $\phi(l, r, \sigma)$ は $(\forall m. l \lt m \lt r \to \sigma^{-1}(m) \lt \sigma^{-1}(l)) \wedge \sigma^{-1}(l) \lt \sigma^{-1}(r)$) な感じのものを求める。
これをさらに式変形すると $O(n)$ になる。

$O(n^2)$ を $O(n)$ にする部分はすごく自動化したい感じする。
翌日の ABC にほぼ同じ問題が出た: <https://atcoder.jp/contests/abc151/tasks/abc151_e>

## D - Arrangement

問題をグラフで言うとつまり次である:
補グラフが functional グラフであるような $N$ 頂点 ${} _ N C _ 2 - N$ 辺のグラフが与えられる。長さ $N$ の単純パスの存在を判定し、存在するなら辞書順最小のものを求めろ。

ハミルトン路とはいえほぼ完全グラフなのでほとんど常に存在することが予想できる。
特に、愚直な全探索を書いてもほとんどのケースで $\Theta(N)$ で解ける。
ただしたとえば次のようなケースがまずい:

```
10
10 10 10 10 10 10 10 10 10 1
```

```
10
10 10 10 10 1 10 10 10 10 1
```

これを対策するには区間最大値のセグメント木などを使えばよい。
これで $O(N \log N)$ になり、他にまずいケースはないので通る (未証明)。
ちなみにパスは $N \ge 3$ なら常に存在する (未証明)。


## リンク

-   <https://atcoder.jp/contests/dwacon6th-prelims>
