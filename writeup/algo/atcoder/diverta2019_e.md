---
redirect_from:
layout: post
date: 2019-05-11T23:59:59+09:00
tags: ["competitive", "writeup"]
---

# diverta 2019 Programming Contest: E - XOR Partitioning

## 問題

数列 $A = (a_1, a_2, \dots, a_n)$ が与えられる。
この数列に $0$ 個以上の区切りを入れていくつかの非空な区間に分割し $((a_1, a_2, \dots, a _ {s_1}), (a _ {s_1 + 1}, a _ {s_1 + 2},  \dots, a _ {s_2}), \dots, (a _ {s _ {k - 1} + 1}, a _ {s _ {k - 1} + 2}, \dots, a_n))$ とすることを考える。
これは $2^{N-1}$ 通り考えられるが、分割されたそれぞれの区間中の要素すべての排他的論理和 $a _ {s_i + 1} \oplus \dots \oplus a _ {s _ {i + 1}}$ を計算したとき、それらがすべての区間について同一になるようなものはいくつあるか答えよ。

## 解法

まず累積 xor を取る。
すると区切りを入れるべき位置は累積 xor の値が $a, 0, a, 0, \dots$ と交互になるような位置であることが分かる。
丁寧に行えば $O(N)$ で、雑にやると $O((N + \max A) \log \max A)$ などで計算できる。

## 考察過程再現

1.  とりあえず累積 xor 取りたい
1.  $a_i \lt 2^{20}$ の制約は怪しい
1.  $\mathrm{dp}(r, b)$ を最後に $r$ 番目まで見使って区間 xor の値がすべて $b$ な区切り方の数とすると $$\mathrm{dp}(r, b) = \sum _ {l \lt r ~ \land ~ a_l \oplus \dots a _ {r - 1} = b} \mathrm{dp}(l, b)$$ になって $O(N^2 \max A)$
1.  $\mathrm{dp}(r, b, c)$ を $r$ 番目まで見て区間 xor の値がすべて $b$ で最後の区間は $c$ な区切り方の数とするはだめ
1.  補集合を数えよう
1.  区間 xor が $a, a, a, \dots, a$ ときて始めて不一致 $b$ になる位置を考えることになれば、状況は何も変わっていない
1.  $\mathrm{dp}(l, r, b)$ を考えるとどうか。区間 $[l, r)$ 内に制限したときの、区間 xor がすべて $b$ になるような区切り方の数とする。これは $O(N^3 \max A)$ ぽい
1.  $b \oplus b = 0$ や $b \oplus b \oplus b = b$ を使って上手くやれないか
1.  累積 xor の値が同一の値 $b$ であるような位置 $l, r$ があったとき、区間 $[l, r)$ の xor の値は $0$ になる。これを用いれば、区間 xor が $0$ な区間はすべて分かったとしてよい
1.  逆に、区間 xor が $0$ な区間 $[l, r)$ に対し、部分区間 $[l, m), [m, r)$ を考えるとそれらの区間 xor の値は同一
1.  $\mathrm{dp}(l, r)$ を $r$ 番目まで適切に区切り、特に最後の区間が $[l, r)$ であったものの数とする。これは $$\mathrm{dp}(m, r) = \sum _ {l \lt m ~ \land ~ a_l \oplus \dots a _ {m - 1} = 0} \mathrm{dp}(l, m)$$ となる
1.  $2$ 変数から加速するために $\mathrm{dp'}(r) = \sum _ {m \lt r} \mathrm{dp}(m, r)$ とおく。すると $$\mathrm{dp'}(r) = \sum _ {m \lt r} ~ \sum _ {l \lt m ~ \land ~ a_l \oplus \dots a _ {m - 1} = 0} \mathrm{dp}(m, r) = \sum _ {l \lt m \lt r ~ \land ~ a_l \oplus \dots a _ {m - 1} = 0} \mathrm{dp}(m, r)$$ となる。よさそう
1.  (よさそうだけど詰められない)
1.  全体の xor の値 $\bar{a} = a_1 \oplus a_2 \oplus \dots \oplus a_n$ が $0$ であるかで場合分けをするとよさそう。$0$ でない場合は区間 xor の値として $\bar{a}$ のみを考えればよいので解ける
1.  $\bar{a} = 0$ の場合は任意の位置にひとつだけ区切りを入れると妥当な分割 $b \oplus b = 0$ になる
1.  その一方を $3$ 分割して $b = b \oplus b \oplus b$ としたい
1.  この図を書くと累積 xor の値が $0, b, 0, b, 0$ と交互に出ることが分かる
1.  これを数えれば解けそう
1.  $\mathrm{dp}(r, b)$ を最後に位置 $r$ を区切りに使い区間 xor は $b$ のものを考えた場合の数とする。例えば位置 $r$ の累積 xor が $0$ のき $$\mathrm{dp}(r, b) = \sum _ {l \lt r ~ \land ~ a_1 \oplus \dots \oplus a _ {l - 1} = b} \mathrm{dp}(l, b)$$ とでき、これは上手くまとめれば解けそう
1.  (細部を詰めつつ頑張って実装)
1.  時間かかったけどできた

## 反省

-   時間内に解けなかった (1時間40分かかった、30秒ほど遅かったので提出できず)。 tempura0224 など速い人は $22$ 分とかで通してるので遅い。
-   考察過程を見返すと特にどこが問題とも思えないので困った。強いて挙げれば「累積 xor を中心に整理するのが遅かった」とかだろうか
-   なぜかセグ木を植えてしまった

## 教訓: 群 $(M, \cdot, e)$ 上の区間集約 $a_l \cdot a _ {l + 1} \cdot \dots \cdot a _ {r - 1}$ に関する問題は常に累積和での言い換えを検討すべき

累積和 $A$ を使って $a_l \cdot a _ {l + 1} \cdot \dots \cdot a _ {r - 1} = A_r \cdot A_l^{-1}$ と置き換えるのは常に可能であり、何らかの損失も発生しない。「とりあえず補集合」と同じ流れで「とりあえず累積和」してもよさそう

## メモ

セグ木を誤植した人は私以外にもいた:

<blockquote class="twitter-tweet"><p lang="ja" dir="ltr">Eでセグ木か？セグ木？ウーンっていいながらラムダ式書いたところで全体更新と一点更新しかしないことに思い当たって全部消した</p>&mdash; beet (@beet_aizu) <a href="https://twitter.com/beet_aizu/status/1127223553563041792?ref_src=twsrc%5Etfw">May 11, 2019</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

<blockquote class="twitter-tweet"><p lang="ja" dir="ltr">Eは0が来たらなんか全部足さないといけないから遅延セグ木で保存しとけばいけそうと思って遅延セグ木を大幅改造した</p>&mdash; tatyam (@tatyam_prime) <a href="https://twitter.com/tatyam_prime/status/1127224275369283584?ref_src=twsrc%5Etfw">May 11, 2019</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

## リンク

-   <https://atcoder.jp/contests/diverta2019/tasks/diverta2019_e>
-   <https://atcoder.jp/contests/diverta2019/submissions/5368692>
