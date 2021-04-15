---
redirect_from:
  - /writeup/algo/topcoder/768div1medium/
layout: post
date: 2019-10-11T23:59:59+09:00
tags: ["competitive", "writeup"]
---

# SRM 768 Div 1: Medium. PBG

## 問題

polar bears が $P$ 匹、brown bears が $B$ 匹、grizzly bears が $G$ 匹おり、これらでトーナメントをする。
次を繰り返す: ランダムに $2$ 匹取り出し、戦わせ、負けた方が去る。
同種の熊なら等確率でどちらかが勝ち、異種の熊なら brown $\lt$ polar $\lt$ grizzly という強さの順序で勝敗が決まる。
去った順番の逆順で順位が定まる。
さて polar bear である熊の Limak の順位の期待値はいくつか。

## 考察過程 (本番中)

-   $O(PBG)$ の DP を書いて高速化だろうか？
-   とりあえず $B = 0$ にして考えて、後から差し込む感じはどうか
-   分からないから先に愚直解を書いてから実家を考えたい
-   バグりました

## 考察過程 (復習)

-   熊 $A$ と熊 $B$ を選んで戦わせるところで、$A$ の側の選び方の数を掛け忘れていた
-   再帰先の期待値を常に $1$ にして、全体の確率の総和がちゃんと $1$ になってることを確認するべきぽい
-   Limak は polar bears の中でも平均的な強さを持つとしてよく、$P$ を $B, G$ に分配できる
    -   $\to$ 嘘でした
-   ちょうど平均的な強さを持つとするのでなくて、$i \in \lbrace 1, 2, \dots, P \rbrace$ 番目に強い場合すべてを試せばよい
-   愚直 DP を再利用して $O((B + P)(G + P))$ の DP ではい
    -   $\to$ 最大ケースで手元 $5.3$ sec ですが……
-   簡単に定数倍したら $0.9$ sec まで落ちた

## 解法

$O(PBG)$ 愚直 DP が可能なのは明らかだが、いくらか間に合わない。
ここでもし $P = 1$ であれば解けそうである。そのように見なす方法を考えよう。
同種の熊の戦闘時の結果を固定し、polar bears の中での Limak の強さが $i \in \lbrace 1, 2, \dots, P \rbrace$ 番目だった場合を考える。それらすべてを計算し、その平均が答えである。
これは $(P', B', G') = (1, B + P, G + P)$ とした上で解く事に等しい。
よって愚直 DP を利用して $O((B + P)(G + P))$ で解ける。

## 解法 (editorial)

だいたいの方向性は同じ。
ただし補集合を数えるようにして、Limak が brown / grizzly だった場合を考え、$O((B + P)G + B(P + G))$ で解く。

## メモ

-   Q. なぜ解けなかった？
    -   A. 愚直解をバグらせて時間が消えたため
-   方針が曖昧なまま「とりあえず実装してから考えよう」はやめた方がよさそう

## リンク

-   editorial: <https://docs.google.com/document/d/1XbeqZMHsNjv2J3h8x0PsJnBn4IV8llJx9hT39iQkOcY/edit>
