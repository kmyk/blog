---
redirect_from:
  - /writeup/algo/atcoder/abc130/
layout: post
date: 2019-06-30T23:59:59+09:00
tags: ["competitive", "writeup"]
---

# AtCoder Beginner Contest 130

E まで典型そのままなのに F だけ面倒で難易度勾配が崖だなあと思ったが、そうでもなかった。
F の嘘が通ってしまったらしいからか。

## D - Enough Array

しゃくとり法をそのままやるだけ。$\Theta(N)$。

## E - Common Subsequence

DP。$\mathrm{dp}(i, j)$ を「$S$ の先頭 $i$ 要素までと $T$ の先頭 $j$ 要素までを使って作れる一致する部分列の組の数」とする。
二次元累積和とか包除原理ぽくやると $\Theta(NM)$。

## F - Minimum Bounding Box

$x, y$ 軸上を線分が速度 $-1, 0, 1$ で動く。
軸ごとに考えると区分的に $1$ 次関数がでてくるのでいい感じにやる。
計算量は前処理 $\Theta(N)$ して本質部分は $O(\log \max(\max_i x_i, \max_i y_i))$ とかになる。

$f(t) = x _ \max (t) - x _ \min (t)$ とおくと、この $f$ は区分的に $1$ 次関数。
$g(t) = y _ \max (t) - y _ \min (t)$ も区分的に $1$ 次関数。
よって時刻 $t$ の動く区間 $[0, \infty)$ を $k$ 個の区間 $[0, r_1), [l_2, r_2), \dots, [l_k, \infty)$ に分けて、$f, g$ を $[l_i, r_i]$ に制限すると共に $1$ 次関数であるようにできる。

さて、このようにして求まった $1$ 次関数 $f, g : [l, r] \to \mathbb{R}$ に対し $\min _ {x \in [l, r]} f(x)g(x)$ を求めたい。
$f(x) = ax + b, \; g(x) = cx + d$ とおくと $f(x)g(x) = acx^2 + (ad + bc)x + bd$ となる。
$ac \le 0$ のときこれは上に凸関数なので最小値は $x = l$ または $x = r$ となる。
$ac \gt 0$ とする。このときは下に凸関数であるので一般には最小値は $x = l$ でも $x = r$ でもないことがある。
しかしこの問題においては $\forall x \in [l, r]. \; f(x), \, g(x) \ge 0$ を仮定してもよく、すると $f(x)g(x)$ は下に凸な $2$ 次間数の右側部分だけということになるので、やはり最小値は $x = l$ または $x = r$ となる。

### メモ

-   $\min _ {x \in [l, r]} f(x)g(x)$ の部分をとりあえず三分探索してしまった
-   全体を三分探索するという嘘解法が通るらしい
    <blockquote class="twitter-tweet"><p lang="ja" dir="ltr">ABC 130: 今回は C に変なのを置く代わりに D 以降は真面目なもので固めました。F の三分探索はできるだけ落とすべきでしたが結構通ってしまったようです、すみません。</p>&mdash; えびま (@evima0) <a href="https://twitter.com/evima0/status/1140252826871840769?ref_src=twsrc%5Etfw">June 16, 2019</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

## リンク

-   <https://atcoder.jp/contests/abc130>
-   D <https://atcoder.jp/contests/abc130/submissions/6187737>
-   E <https://atcoder.jp/contests/abc130/submissions/6188060>
-   F <https://atcoder.jp/contests/abc130/submissions/6188680>
