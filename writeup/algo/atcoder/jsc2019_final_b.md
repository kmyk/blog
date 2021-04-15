---
redirect_from:
  - /writeup/algo/atcoder/jsc2019_final_b/
layout: post
date: 2019-10-03T23:59:59+09:00
tags: ["competitive", "writeup"]
---

# 第一回日本最強プログラマー学生選手権決勝: B - Reachability

## 解法

とりあえず制約を整理すると答えになる。
辺を張れる限り張ってみて、それが制約を満たしているか判定 (典型)。
$y_j \to z_k$ の辺が張ってあることを $C _ {j, k}$ と書くと、問題文より、辺 $C _ {j, k}$ を張っても制約違反しない $\iff \forall i. A _ {i, j} \to B _ {i, k} \iff \lnot \exists i. A _ {i, j} \wedge \lnot B _ {i, k}$ である。
$O(N^3)$ だが `std::bitset<>` が可能。

## リンク

-   <https://atcoder.jp/contests/jsc2019-final/tasks/jsc2019_final_b>
