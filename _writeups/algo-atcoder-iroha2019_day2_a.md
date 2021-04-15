---
redirect_from:
  - /writeup/algo/atcoder/iroha2019_day2_a/
layout: post
date: 2019-05-11T23:59:59+09:00
tags: ["competitive", "writeup"]
---

# いろはちゃんコンテスト Day2: A - わたのはら

## 問題

文字列 $S$ に対し $f(S, k)$ を $S$ の長さ $k$ の部分列の全体の集合とする。
文字列 $S, T$ が与えられるので、$f(S, q) \cap f(T, q) = \emptyset$ を満たすような最小の $q$ を答えよ。

## 解法

最長共通部分列 LCS の長さ $l$ を求めて、 $l + 1$ が答え。
計算量は $O(|S| \cdot |T|)$ となる。

## メモ

最長共通部分列は愚直 DP で $O(|S| \cdot |T|)$ で求めればよい。
競プロにおいてはこれが最速と思ってよさそう？

## 検討: 最長共通部分列に帰着できたのはなぜか

帰着の流れは以下のようなものであった:
条件 $f(S, q) \cap f(T, q) = \emptyset$ を $\varphi(q)$ と書くことにする。
このとき単調性 $\forall q. ~ \varphi(q) \to \varphi(q + 1)$ が言える。
ここからただちに $\min \{ q \in \mathbb{N} \mid \varphi(q) \} = \max \{ q \in \mathbb{N} \mid \lnot \varphi(q) \} + 1$ という双対定理の形の式が得られる。
このとき $\max \{ q \in \mathbb{N} \mid \lnot \varphi(q) \}$ は明らかに最長共通部分列の長さである。

この流れをまとめると、条件 $\varphi(q)$ の単調性によって、否定 $\lnot \varphi(q)$ を考えればよくなったため、と答えられる。

## リンク

-   <https://atcoder.jp/contests/iroha2019-day2/submissions/5338305>
-   <https://atcoder.jp/contests/iroha2019-day2/tasks/iroha2019_day2_a>
