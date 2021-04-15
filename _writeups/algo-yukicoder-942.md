---
redirect_from:
  - /writeup/algo/yukicoder/942/
layout: post
date: 2019-12-06T23:59:59+09:00
tags: ["competitive", "writeup"]
---

# yukicoder No.942 プレゼント配り

## 解法

以下の $3$ つの自明な必要条件が十分条件でもある:

1.  必要条件: $K \mid N$
    -   これを仮定し $M = N / K \in \mathbb{N}$ とおく
1.  必要条件: $K \mid \sum_i i = N (N + 1) / 2$
    -   整理すると $2 \mid M (N + 1)$
1.  必要条件: $N = K = 1 \vee M \ne 1$

まず自明な十分条件を確認する:

-   十分条件: $2 \mid M$
    -   $i$ 番目の子供に $\lbrace \sigma(xK + i) \mid x \lt M \rbrace$ を配るとして $\sigma = (1, 2, 3, \dots, K; K, K - 1, K - 2, \dots, 1; \dots)$ とすればよい
    
残りは $M, N$ 共に奇数のときである。$M - 3$ 個は $2 \mid M$ のときと同様にすることにして $M = 3$ を仮定してかまわない。
このとき $K$ も奇数である。
中央値 $c = (K + 1) / 2 \in \mathbb{N}$ とおいて $\sigma = (1, 2, 3, 4, 5, \dots, K - 4, K - 3, K - 2, K - 1, K; c + 1, c + 2, c + 3, c + 4, c + 5, \dots, c - 4, c - 3, c - 2, c - 1, c; c, K, c - 1, K - 1, c - 2, \dots, 3, c + 2, 2, c + 1, 1)$ とすれば上手くいく。

## メモ

-   最後の $M = 3$ の場合までの整理はできていた (自明なので) がそこからがだめ。解説を見ました。だめうさぎ

## リンク

-   <https://yukicoder.me/problems/no/942>
-   提出: <https://yukicoder.me/submissions/405634>
