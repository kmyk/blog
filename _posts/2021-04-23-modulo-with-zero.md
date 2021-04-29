---
category: blog
layout: post
date: 2021-04-23T00:00:00+09:00
updated: 2021-04-29T00:00:00+09:00
---

# mod で計算するときに零の重複度も持つテク

## 概要

通常の整数の乗除算を、計算過程に出現する数の最大値を小さくするなどの目的で、ある $p$ に対して $\bmod~ p$ で計算することがあります。
しかし、$p$ が途中に出現する数より小さい場合には、もともとは $0$ ではないのだが $\bmod~ p$ では $0$ になってしまうような数が問題となることがあります。
このような場合には、整数 $a$ に対して $b = a ~\bmod~ p$ の値だけでなく、その整数 $a$ が約数として $p$ をいくつ含むかの数 $c$ も管理するとうまくいくことがあります。
つまり $a = b p^c$ に対して単に $b$ のみを持つのでなく組 $(b, c)$ を持つようにするとうまくいくことがあります。
また、計算の過程では $c \lt 0$ のような組 $(b, c)$ を許して考えると便利です。


## 例題 1: AtCoder Regular Contest 117: C - Tricolor Pyramid

URL: <https://atcoder.jp/contests/arc117/tasks/arc117_c>

この問題の想定解法は以下のふたつのパートに分かれています。

1.  mod 文字種で考えて立式する
2.  ${} _ n C _ r ~\bmod~ 3$ をたくさん高速に計算する

この問題で議論するのは後者の部分です。
これは通常の ${} _ n C _ r ~\bmod~ (10^9+7)$ など場合と同様にはできません。
${} _ n C _ r = \frac{n!}{r! \cdot (n-r)!}$ という関係式を使って ${} _ n C _ r ~\bmod~ 3$ を計算するとき、右辺の除算の上下に $0$ が出てきてしまうことがあるためです。
たとえば ${} _ 5 C _ 3 ~\bmod~ 3 = 10 ~\bmod~ 3 = 1$ を計算したいときに $\frac{5!}{3! \cdot (5 - 3)!} \equiv \frac{0}{0 \cdot 2}$ となってしまい計算ができません。

そこで今回のテクを使います。
通常は $\bmod~ p$ での階乗 $a_n = n! ~\bmod~ p$ を事前に計算しますが、この問題では $n! = b_n p^{c_n}$ とおいて組 $(b_n ~\bmod~ p, c_n)$ を事前に計算して持っておきます。
そしてこの組の上で適切に演算をします。
具体的には、乗算は $(b_1, c_1) \cdot (b_2, c_2) = (b_1 b_2 ~\bmod~ p, c_1 + c_2)$ となり、$p \nmid b$ のとき逆元は $(b, c)^{-1} = (b^{-1}, - c)$ となります。
そして最後に組 $(b, c)$ から所望の値 $b p^c ~\bmod~ p$ を得ます。
この値は $c = 0$ ならば $b$ であり、$c \ge 1$ ならば $0$ です。

たとえば ${} _ 5 C _ 3  ~\bmod~ 3$ を計算したいときを考えましょう。
$5! = 40 \cdot 3^1$ かつ $3! = 2 \cdot 3^1$ かつ $2! = 2 \cdot 3^0$ であるので、整数 $5!, 3!, 2!$ に対応する組はそれぞれ $(1, 1), (2, 1), (2, 0)$ です。
整数と対応する組とを同一視して置き換えると $\frac{5!}{3! \cdot (5 - 3)!}$ は $\frac{(1, 1)}{(2, 1) \cdot (2, 0)}$ であり、これを計算すると $\frac{(1, 1)}{(2, 1) \cdot (2, 0)} = (1, 1) \cdot (2, -1) \cdot (2, 0) = (1, 0)$ となります。
組 $(1, 0)$ に対応する整数は $1 \cdot 3^0 ~\bmod~ 3 = 1$ であるので、これで $0$ を回避して $\frac{5!}{3! \cdot (5 - 3)!} ~\bmod~ 3 = 1$ の計算ができました。

## 例題 2: yukicoder No.1141 田グリッド

URL: <https://yukicoder.me/problems/no/1141>

これは次のような問題です。

-   $H \times W$ の行列 $A$ (ただし $0 \le A _ {y, x} \le 10^9$) が与えられる。次のようなクエリ $(r_i, c_i)$ がたくさん与えられるのですべて処理せよ: $A$ から $r_i$ 行目と $c_i$ 列目を削除してできる $(H - 1) \times (W - 1)$ 行列の要素の総積 $\mathrm{ans} _ i = \prod _ {y \ne r_i} \prod _ {x \ne c_i} A _ {y, x} ~\bmod~ (10^9+7)$ を答えよ。

この問題を解くための方法として、包除原理を用いたようなものがまず思い付くでしょう。
つまり、全体の総積 $f = \prod _ y \prod _ x A _ {y, x}$ と各行の総積 $g_y = \prod _ x A _ {y, x}$ と各列の総積 $h_x = \prod _ y A _ {y, x}$ とを事前に計算しておき、$\mathrm{ans} _ i = f \cdot g _ {r_i} ^ {-1} \cdot h _ {c_i} ^ {-1} \cdot A _ {r_i, c_i} ~\bmod~ (10^9+7)$ とする、というものです。
しかしこれはそのままではうまくいきません。
制約から $A _ {y, x} = 0$ が入力されることがあり、$g _ {r_i} ^ {-1}$ や $h _ {c_i} ^ {-1}$ が計算できないことがあるためです。

$0$ とそれ以外とを別々に処理することでこの $0$ の問題に対処できます。
$(H - 1) \times (W - 1)$ 行列中にひとつでも $0$ が含まれれば $\mathrm{ans} _ i = 0$ であり、そうでなければ $0$ を無視して (つまり $1$ で置き換えて) 計算した結果が $\mathrm{ans} _ i$ です。
$(H - 1) \times (W - 1)$ 行列中にいくつの $0$ が含まれるのかは、全体にいくつ $0$ が含まれるかから、$r_i$ 行目にいくつ $0$ が含まれるかと $c_i$ 列目にいくつ $0$ が含まれるかを引き、$A _ {r_i, c_i}$ が $0$ であるかに応じて $1$ を足すことで求められます。
これは入力中の $A _ {y, x} = 0$ を $10^9 + 7$ だったと思って今回のテクを使っているものだと見ることができます。


## 理論

### Laurent 多項式

通常の多項式の拡張として、Laurent 多項式と呼ばれるものがあります。
これは負冪を許すような多項式のことです。
$R$ を可換環とし、通常の多項式 $f \in R \lbrack x \rbrack$ は自然数 $r \in \mathbb{N}$ と係数列 $(a_0, a _ 1, \dots, a _ {r - 1})$ を使って $f = \sum _ {i = 0} ^ {r - 1} a_i x^i$ と書けますが、これに対して Laurent 多項式 $f$ は整数 $l, r \in \mathbb{Z}$ (ただし $l \le r$) と係数列 $(a_l, a _ {l + 1}, \dots, a _ {r - 1})$ を使って $f = \sum _ {i = l} ^ {r - 1} a_i x^i$ と書かれます。
この Laurent 多項式からなる環を Laurent 多項式環と呼び $R \lbrack x, x^{-1} \rbrack$ と書きます。
なお、Laurent 多項式環は群環 $R \lbrack \mathbb{Z} \rbrack$ と同型です。

整域[^domain] $R$ 上の Laurent 多項式環 $R \lbrack x, x^{-1} \rbrack$ の元 $f \in R \lbrack x, x^{-1} \rbrack$ について、それが単元[^unit]であることとそれが単元を係数とする単項式であることは同値です。
ただし Laurent 多項式環 $f \in R \lbrack x, x^{-1} \rbrack$ が単項式であるとはある係数 $a \in R$ とある整数 $i \in \mathbb{Z}$ が存在して $f = a x^i$ と書けることとします。
つまり $(R \lbrack x, x^{-1} \rbrack)^{\times} = \lbrace a x^k \mid a \in R^{\times} \wedge k \in \mathbb{Z} \rbrace \simeq R^{\times} \times \mathbb{Z}$ が成り立ちます。
証明は省略します[^proof]。

$p$ を素数とし $a = b p^c$ (ただし $p \nmid b$) に対する組 $(b, c)$ に今回のテクの演算を入れたものは、体 $\mathbb{F} _ p$ の Laurent 多項式環 $\mathbb{F} _ p \lbrack x, x^{-1} \rbrack$ の単元全体からなる群 $(\mathbb{F} _ p\lbrack x, x^{-1} \rbrack)^{\times}$ を $x = p$ という想定の下で考えているものだと思えます。
つまり今回のテクで用いられる組 $(b, c)$ は $0$ でない単項式 $b x^c \in (\mathbb{F} _ p\lbrack x, x^{-1} \rbrack)^{\times}$ です。
$0$ でない単項式 $b x^c$ から $a ~\bmod~ p$ の値を取り出すときは $b p^c ~\bmod~ p$ の値を計算すればよいです。
$c = 0$ ならば $a ~\bmod~ p = b$ となり $c \ne 0$ ならば $a ~\bmod~ p = 0$ となります。


### $p$ 進数

Laurent 多項式を正の次数の項の無限和を許すように拡張したものを形式的 Laurent 級数と呼びます。
形式的 Laurent 級数 $f$ は整数 $l \in \mathbb{Z}$ と体 $K$ の要素の無限列 $(a_l, a _ {l+1}, a _ {l+2}, \dots)$ を使って $f = \sum _ {i = l} ^ {\infty} a_i x^i$ と書かれます。
体 $K$ の要素を係数とする形式的 Laurent 級数の全体は体をなし、この体を形式的 Laurent 級数体と呼び $K((x))$ と書きます。

$p$ を素数としたとき、自然数 $n \in \mathbb{N}$ はある整数 $r \in \mathbb{Z}$ と $0$ 以上 $p$ 未満の整数の列 $(a_0, a_1, \dots, a _ {n-1})$ を使って $n = \sum _ {i = 0} ^ {n - 1} a_i p^i$ と書けます。
これを無限和を許すように拡張してできる数 $\sum _ {i = 0} ^ {\infty} a_i p^i$ のことを $p$ 進整数と呼び、これをさらに負冪を許すように拡張してできる数 $\sum _ {i = l} ^ {\infty} a_i p^i$ のことを $p$ 進数と呼びます。
$p$ 進数全体からなる体を $p$ 進数体と呼び $\mathbb{Q} _ p$ と書きます。

形式的 Laurent 級数と $p$ 進数には記法上の類似があります。
今回のテクでは Laurent 多項式環の係数として体 $\mathbb{F} _ p$ を用いているため、今回のテクで用いられる組 $(b, c)$ は形式的 Laurent 級数を介して $p$ 進数だと思うことができます。
つまり単項式 $b x^c \in (\mathbb{F} _ p\lbrack x, x^{-1} \rbrack)^{\times}$ でなく $p$ 進数 $b p^c \in \mathbb{Q} _ p$ を用いて今回のテクを説明することも可能です。
ただし形式的 Laurent 級数体 $\mathbb{F} _ p ((x))$ と $p$ 進数体 $\mathbb{Q} _ p$ とが同型になるわけではないので、このことに起因する差には注意が必要です。
$b_1 p^{c_1} \cdot b_2 p^{c_2} = (b_1 b_2 ~\bmod~ p) p^{c_1 + c_2}$ とは限らず、また $b p^c \in \mathbb{Q} _ p$ の形の項の全体は乗法で閉じていません。
このため、一般の $p$ 進数を最低次数の係数のみを考えながら (つまり適切に近似しながら) 演算するという形になります。


## 参考文献

-   雪江明彦, [代数学3 代数学のひろがり](https://www.amazon.co.jp/dp/4535786615)
    -   p126 の $p$ 進体のあたりや p139 形式的冪級数体のあたりを参考にした


## クレジット

この記事は私と [@elliptic_shiho](https://twitter.com/elliptic_shiho) との間での議論をまとめたものです。
テクニックとしての整理は私が行い、その背景の理論として Laurent 多項式環 $\mathbb{F} _ p \lbrack x, x^{-1} \rbrack$ を使うアイデアは [@elliptic_shiho](https://twitter.com/elliptic_shiho) が出しました。
$p$ 進数体 $\mathbb{Q} _ p$ との接続も [@sugarknri](https://twitter.com/sugarknri) による[言及](https://twitter.com/sugarknri/status/1385421416825163778)をもとに [@elliptic_shiho](https://twitter.com/elliptic_shiho) が説明してくれました。


## 更新履歴

-   2021 年 4 月 29 日: 有理関数体 $\mathbb{Z}/m\mathbb{Z}(x)$ でなく Laurent 多項式環 $\mathbb{F} _ p \lbrack x, x^{-1} \rbrack$ を使う形で理論パートを書き直した。また $p$ 進数体 $\mathbb{Q} _ p$ への言及を追加した。


## 注釈

[^domain]: 整域とは、零因子を持たない可換環であって自明環でないものです。零因子を持たないとはつまり $xy = 0$ なら $x = 0$ か $y = 0$ が成り立つということです。
[^unit]: 単元とは、逆元が存在する元のことです。また、可換環 $R$ の単元全体からなる群を $R^{\times}$ と書きます。
[^proof]: 気になる人は [abstract algebra - Unit group of Laurent polynomial rings - Mathematics Stack Exchange](https://math.stackexchange.com/questions/1423274/unit-group-of-laurent-polynomial-rings) などを読んでください。
