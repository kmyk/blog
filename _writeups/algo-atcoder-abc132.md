---
redirect_from:
  - /writeup/algo/atcoder/abc132/
layout: post
date: 2019-06-29T23:59:59+09:00
tags: ["competitive", "writeup"]
---

# AtCoder Beginner Contest 132

解法は見れば分かるが、さらに進んだ考察をしないと実装で手間取る (特に D と F) 回だった。

## D - Blue and Red Balls

操作回数 $i$ を固定すると、青いボールの配置と赤いボールの配置は独立。
組合せ ${} _ n C _ r$ の計算をやるだけなので $O(N)$。

それぞれ長さ $N, N - K$ の列の中に $i - 1, i$ 個の区切りを入れて分割する感じのやつ。
ただし長さ $0$ でもいい区間とだめな区間に注意する。
私は理解が甘かったので青いボール側は愚直 DP $O(N^2)$ をしてしまったが、十分な理解があれば実装は軽かったはず。

## E - Hopscotch Addict

Dijkstra やるだけ。$O(M \log N)$。

ただし「けん」「けん」「ぱ」のどの位置かの情報をグラフに乗せるため $3 = \{ 0, 1, 2 \}$ との直積 $V \times 3$ の上のグラフで Dijkstra を行う。

## F - Small Products

DP。$O(NK)$ の愚直 DP の状態をまとめることで $O(\sqrt{N} K)$ でやる。
$1, 2, 3, \dots, \lfloor \sqrt{N} \rfloor, (l_1, r_1], \dots, (l _ {\lfloor \sqrt{N} \rfloor}, N]$ という $2 \sqrt{N}$ 個に分割してもよいが、約数を用いての分割をするとより楽。

得られる教訓は「DP の基礎となる整礎関係上で区別できない状態はまとめることができる」「$\sqrt{N}$ 個への分割のときは $N$ の約数を境界とするとよい可能性がある」などか。

<blockquote class="twitter-tweet"><p lang="ja" dir="ltr">D: 青をi個に分割して、赤を{i-1,i,i+1}個に分割<br>E: 各頂点についてmod3で0,1,2ステップ目に訪れるための最短を記録。幅優先<br>F: nの各約数aについてdp[i][a]: i個要素を並べて、最右の要素がa以下でaよりひとつ小さい約数より大きいような場合の数<br>更新は累積和で</p>&mdash; Joe★☆☆☆☆ (@xuzijian629) <a href="https://twitter.com/xuzijian629/status/1144965234219556864?ref_src=twsrc%5Etfw">June 29, 2019</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

## リンク

-   <https://atcoder.jp/contests/abc132>
-   D <https://atcoder.jp/contests/abc132/submissions/6167252>
-   E <https://atcoder.jp/contests/abc132/submissions/6171517>
-   F <https://atcoder.jp/contests/abc132/submissions/6177286>
