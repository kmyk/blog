---
layout: post
date: 2019-12-18T23:59:59+09:00
tags: ["competitive", "writeup"]
---

# AtCoder Regular Contest 044: D - suffix array

## 解法

貪欲に構築できる。全体で $O(N)$。

1.  文字数制約は無視して解いて構わない。
    つまり $\Sigma = \lbrace A, B, C, \dots, Z \rbrace$ でなく $\Sigma = \lbrace 1, 2, 3, \dots, N \rbrace$ で解けば十分である。
2.  ひとまず辞書順最小制約を無視して考える。
    このとき常に $b _ {a_i} = i$ であるような文字列が存在し答えである。
3.  そして辞書順最小制約を考慮して考える。
    辞書順最小のものを $c$ とする (これは $b$ が存在することから自明に存在する)。
    このとき各位置の文字の大小関係は変化しない ($\forall i, j.~ c_i \le c_j \iff b_i \le b_j$) のは明らか。
    ここから、$b$ の要素を詰めていく、つまり suffix array が $a$ となる数列 $b$ の各位置の文字を減らしてもなお suffix array が保たれるかの判定をするような方向で考えたくなる。
    特にこのとき $b, c$ の各文字の順序の制約より、 $b$ 中で $i$ 番目に小さい文字を最小化するように更新することを $i = 2, i = 3, \dots$ についてこの順で行えば十分であることが言える (はず)。
    $b_j, b_k$ を (初期状態で) $i, i + 1$ 番目に小さい文字 (だったもの) として $b_j$ の最小化が済んでいるとし、$b_k$ を最小化したいとき、これは $b _ {j + 1}, b _ {k + 1}$ を比較すればよい。
    $b_k \in \lbrace b_j, b_j + 1 \rbrace$ なのは明らかで、では $b_k = b_j$ にできるかのみ考えればよいためである。
    ただし $b$ の末尾に $0$ を加えておくとよい。

## メモ

-   以前 KokiYmgch と一緒にばちゃで開いて解けなかった記憶があるが、自明だった

## リンク

-   <https://atcoder.jp/contests/arc044/tasks/arc044_d>
-   提出: <https://atcoder.jp/contests/arc044/submissions/9003108>
