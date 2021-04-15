---
redirect_from:
  - /writeup/algo/atcoder/abc128_f/
layout: post
date: 2019-11-01T23:59:59+09:00
tags: ["competitive", "writeup"]
---

#  AtCoder Beginner Contest 128: F - Frog Jump

## 解法

妥当な必要条件で絞って平方分割。計算量は $O(N \sqrt{N} (\log N)^2)$ かこれよりも良い。

溺れずにゲームが終了するような組 $(A, B)$ を可能な組と呼ぼう。
組 $(A, B)$ が制約 $1 \le B \lt A \le N - 1$ と $\exists k.~ k (A - B) + A = N - 1$ を満たすことは、可能な組であることの必要条件である。
この必要条件を満たす組は $N = 10^5$ のとき約 $10^6$ 個だけ存在する。
これをすべて試していく。

必要条件を満たす $(A, B)$ が与えられたとする。
実際にこれが可能な組であるか、可能ならばその得点はいくつであるかを計算したい。
$A - B$ が大きければ、愚直に計算して間に合う。
$A - B$ が小さければ、事前に $A - B$ の倍数位置のスコアの総和を計算しておく方向が考えられる。
つまり $f(d, x) = \sum s _ {x + kd} = s_x + s _ {x + d} + s _ {x + 2d} + \dots$ を前処理しておく。
これはかなり丁寧にやる必要があるが、やればできる。
特に、可能性判定のために必要十分条件として $k_1 (A - B) = k_2 (A - B) A$ から導出されるものを考えること、$f(d, x)$ そのままでなくその累積和の形を使うかもしれないことに注意したい。

## 解法 (editorial)

平方分割でなく DP をするが、本質的にはほぼ同じ

## メモ

-   $1$ 時間 $35$ 分
-   `vector<bool>` を毎回リセットするの重くない？ って言って `unordered_set<int>` にしたらすごく遅かった。正解は `vector<int>` で持って判定が `used[x] == current` な初期化可能配列を使うこと。
-   丁寧にやるだけだけどかなりしんどかったです

## リンク

-   <https://atcoder.jp/contests/abc128/tasks/abc128_f>
-   提出: <https://atcoder.jp/contests/abc128/submissions/8244091>
