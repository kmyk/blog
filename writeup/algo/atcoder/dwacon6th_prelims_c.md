---
layout: post
date: 2020-01-23T23:59:59+09:00
tags: ["competitive", "writeup"]
---

# 第6回 ドワンゴからの挑戦状 予選: C - Cookie Distribution

## 解法

求めたい値は $\prod c_i = c_1 c_2 \dots c_N$ である。
$C_i$ を子供 $i$ がクッキーを貰った日付の集合とすると $c_i = \# C_i$ であり、直積 $\prod C_i = C_1 \times C_2 \times \dots \times C_N$ の要素数を数えればよいことが分かる。
これは簡単な $O(KN^2)$ の DP で求まる。

## メモ

-   $i$ 日目に貰ったクッキーと $j$ 日目に貰ったクッキーを区別して考えるのが重要
-   直積 $\prod C_i$ のそれぞれの要素は日付の列 $(d_1, d_2, \dots, d_N) \in \lbrack 1, K \rbrack^N$ である

## リンク

-   <https://atcoder.jp/contests/dwacon6th-prelims/tasks/dwacon6th_prelims_c>
-   提出: <https://atcoder.jp/contests/dwacon6th-prelims/submissions/9681720>
