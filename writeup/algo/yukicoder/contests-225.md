---
redirect_from:
  - /writeup/algo/yukicoder/contests-225/
layout: post
date: 2019-09-27T23:59:59+09:00
tags: ["competitive", "writeup"]
---

# contests 225

## A: No.892 タピオカ

$A_1, A_2, A_3$ の偶奇だけ見ればよい。brainfuck チャンス。$O(1)$。

## B: No.893 お客様を誘導せよ

問題文通りに書くだけ。
$O(N + \sum P_i)$。

## C: No.894 二種類のバス

LCM で包除原理ぽく。$O(\log \max(A, B))$。

## D: No.895 MESE

重要なのは以下の $2$ 点である。$O(a + b + c)$。想定はこれとは違うらしい。

1.  とりあえず制約を整理すると $a + b + c$ 個の bit を $a, b, c$ 個に分配する形になっている。
    このときたとえば問題となっている整数の組 $(x, y, z)$ の個数は ${} _ {a + b + c} C _ {a + b} \cdot {} _ {a + b} C _ a$ である。
2.  $z$ を $2$ 進数展開 $z = \sum _ j z_j 2^j$ して bit ごとに数えればよい。
    求めるのは個数でなく総和 $$\sum _ {\varphi(x, y, z)} z = \sum _ {\varphi(x, y, z)} \sum _ j z_j 2^j$$ であるが、これを $$\sum _ j 2^j \sum _ {\varphi(x, y, z) \land z_j = 1} 1$$ とできる。

## E: No.896 友達以上恋人未満

愚直に書けば間に合う。幾何的に半分にする典型のやつぽさもある。$O(N + \mathrm{MOD} \log \mathrm{MOD})$。嘘解法かも。

まず $z$ を計算しておく。そのまま `vector<int64_t> z(MOD);` でよい。
さてここで $f(a) = \sum _ k z _ {ka}$ をたくさん求めたい。
$f(a)$ の計算量は $\Theta(\mathrm{MOD}/a)$ である。
すべての値を計算しておくことを考えると $\Theta(\mathrm{MOD} \log \mathrm{MOD})$ となり、これは間に合う。
ただし MLE の問題があるので、小さい方から $K$ 個の値のみを計算するようにする。
大きい方はほとんど $O(1)$ なので毎回計算しても問題ない。

## リンク

-   <https://yukicoder.me/contests/237/table>
-   D 実装: <https://yukicoder.me/submissions/384407>
-   E 実装: <https://yukicoder.me/submissions/384554>
