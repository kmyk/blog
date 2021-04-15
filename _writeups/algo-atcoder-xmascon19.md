---
redirect_from:
  - /writeup/algo/atcoder/xmascon19/
layout: post
date: 2019-12-24T23:59:59+09:00
tags: ["competitive", "writeup"]
---

# AtCoder: Xmas Contest 2019

## D - Sum of (-1)^f(n)

くろうさ！

## E - Sum of f(n)

しろうさ！

## J - Sub-Post Correspondence Problem

適当に幅優先で $1$ 秒程度だけ試す嘘が通りました。

-   [決定不能問題ギャラリー (Gallery of Undecidable Problems) - iso.2022.jp](http://iso.2022.jp/math/undecidable-problems/#post-correspondence-problem)
-   提出: <https://atcoder.jp/contests/xmascon19/submissions/9115084>

## K - Set of Trees

これかなりすき

1.  競プロの問題で Cantor 標準形を考えることになるとは……
1.  順序数 $\alpha \lt \epsilon_0$ に対し Grundy 数 $g(\alpha) \in \omega$ を割り当てる。
    まず $n \in \omega$ の場合はそのまま nim なので明らかに $g(n) = n$ である。
    $g(\omega + n) = n$ である。
1.  $g : \epsilon_0 \to \epsilon_0$ と $\oplus : \epsilon_0 \times \epsilon_0 \to \epsilon_0$ にうまく拡張してそのままできないか？
    局面 $(\alpha, \alpha)$ が必敗なのは $\alpha \ge \omega$ でも変わらないし。
1.  自然数個の山は先に排他的論理和してもよいか？ つまり $G : \epsilon_0^{\lt \omega} \to \epsilon_0$ を考えたとき $G(\omega, 1, 2) = G(\omega, 1 \oplus 3)$ などになるか？ なりそう
1.  単純に $(\omega + 1) \oplus (\omega + 2) = 3$ と定義するのは嘘っぽい。
    局面 $(\omega + 1, \omega + 2, 3)$ からは初手 $(\omega + 1, \omega, 3)$ にすると相手は $(\omega, \omega, 3)$ か $(\omega, n)$ にするしかないがどちらも次で $(\alpha, \alpha)$ の形にできる。
1.  一般に局面 $(\omega + a, \omega + b, c)$ に対し先に $\omega$ 個の山を取った方が負け。これは局面 $(a, b, c)$ の勝敗に等しい。
1.  一般に局面 $(\omega + a, \omega + b, \omega + c, d)$ ではどうですか？ 先手は任意の $c'$ に対し $(\omega + a, \omega + b, c')$ へ遷移できるので先手必勝です。
1.  これって Cantor normal form $\alpha = n_0 \omega^{\alpha_0} + \dots + n _ {k-1} \omega^{\alpha _ {k-1}}$ で書いて有限列 $(n_0, \dots, n _ {k-1})$ の各点の排他的論理和を取り、すべて $0$ かどうか見るだけだったりしない？
1.  部分点 ACした。あとは文字列の持ち方を適当にすれば通るでしょ
1.  $\alpha = n_0 \omega^{\alpha_0} + \dots + n _ {k-1} \omega^{\alpha _ {k-1}}$ と書いたときの $\alpha_i \lt \alpha_j$ のような順序はまったく使ってないので、単に根付き木の hash でよい
1.  AC 🎉

-   [ヒドラゲーム | 巨大数研究 Wiki | Fandom](https://googology.wikia.org/ja/wiki/%E3%83%92%E3%83%89%E3%83%A9%E3%82%B2%E3%83%BC%E3%83%A0)
-   提出: <https://atcoder.jp/contests/xmascon19/submissions/9118930>

## リンク

-   <https://atcoder.jp/contests/xmascon19>
-   <http://snuke.main.jp/contest/xmas2019/>
