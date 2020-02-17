---
layout: post
date: 2019-08-09T23:59:59+09:00
tags: ["competitive", "writeup"]
---

# SRM 657 Div 1: Easy. ProblemSets

## 問題

整数 $E, \mathrm{EM}, M, \mathrm{MH}, H$ が与えられる。
$$\max \left\{ \min \{ E', M', H' \} \mid E' = E + x, ~ M' = (\mathrm{EM} - x) + M + y, ~ H' = (\mathrm{MH} - y) + H \right\}$$
を求めよ。

あるいは、次の整数計画問題を解け:

-   max: $x _ {E,M,H} + x _ {E,M,MH} + \dots$
-   sub.to:
    -   $x _ {E,M,H} + x _ {E,M,MH} + \dots \le E$
    -   $x _ {EM,M,H} + x _ {EM,M,MH} + \dots \le \mathrm{EM}$
    -   $\dots$

## 考察

1.  やるだけぽい見ため
1.  あっ 微妙にめんどう
1.  整数計画問題に帰着できたし解けたことにしていい？ だめです。ひゃあ
1.  整数計画問題のいい感じ実装を自動で出力してくれるすごいツールがほしいよう
1.  まあこういうのはたいてい $1$ 点固定すると残りが自明に解けるんですよね
1.  単調性の証明が自明でないし二分探索やだなあ

## 解法

$\mathrm{EM}$ を $E + M$ にどう分けるかを二分探索する。
これが固定されたとき $\mathrm{MH}$ を $M + H$ にどう分けるかは明らか。
全体で $O(\log \mathrm{EM})$ で解ける。

## 反省

-   ぐだぐだやったとはいえ 54 分かかったので青パフォです。だめ

## メモ

-   $x$ を動かしたときの $E', M', H'$ の動きはそれぞれ区分的に $1$ 次間数である。特にその向きと、式が $\min \{ E', M', H' \}$ の形であることから、単調性が従う
-   難易度 Easy, Medium, Hard に加えて難易度 Ultimate を足したとしたら解けるか？
    -   $\mathrm{MH}$ に関して二分探索すればできそう？  $\to$ たぶんできる
    -   なお整数計画問題だしつよいソルバで殴ればいけるのでは？

## リンク

-   問題 <https://community.topcoder.com/stat?c=problem_statement&pm=13771>
