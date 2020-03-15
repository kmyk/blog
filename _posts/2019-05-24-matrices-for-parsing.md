---
category: blog
layout: post
redirect_from:
    - "/blog/2019/05/23/matrices-for-parsing/"
date: 2019-05-24T00:00:00+09:00
tags: [ "competitive", "matrix", "parsing" ]
---

# 行列を用いた構文解析

<small>
前提知識: 行列やベクトルに関する理解と慣れ、正則言語や DFA に関する理解
</small>

## 正規表現

### 説明

正則言語の有限的な性質は同じく有限的な性質を持つ行列と上手く噛み合う。

正規表現は正則言語を表現し、正則言語はそれと等価な決定性有限オートマトン (DFA) を持つ。
記号の全体を $\Sigma$ とする。
正規表現 $\gamma$ が与えられ、対応する DFA $A$ を固定する。
その状態集合を $Q$ とし、遷移関数を $\delta : Q \times \Sigma \to Q$ とする。
ここで文字 $a \in \Sigma$ を固定すれば、そのときの遷移は $\delta(\cdot, a) : Q \to Q$ と書ける。
このような文字に対応する関数 $\delta(\cdot, a) : \Sigma \to \Sigma$ の全体は半群を成す。
それらの $0$ 個以上の結合として文字列に対応する関数の全体はモノイド (syntactic monoid) を成す。
このモノイドの要素はその行列表現を用いて表されることになる。
特に、それぞれの文字が $\mathbb{F} _ 2$ 上の $|Q| \times |Q|$ 行列に対応すると言える。

### 例

記号の全体を $\Sigma = { a, b }$ として、正規表現 `abb*a*` を考える。
これは以下のような DFA と等価になる。

<!--
digraph G {
    graph [ rankdir = LR, bgcolor = "#00000000" ]
    node [ shape = circle, style = filled, fillcolor = "#ffffffff" ]
    init [ style = invis ]
    0 [ label = <q<SUB>0</SUB>> ]
    1 [ label = <q<SUB>1</SUB>> ]
    2 [ label = <q<SUB>2</SUB>> ]
    3 [ label = <q<SUB>3</SUB>> ]
    4 [ label = <q<SUB>4</SUB>> ]
    0 [ rank = source ]
    2 [ shape = doublecircle ]
    3 [ shape = doublecircle ]
    4 [ rank = sink ]
    init -> 0
    0 -> 1 [ label = "a" ]
    1 -> 2 [ label = "b" ]
    2 -> 2 [ label = "b" ]
    2 -> 3 [ label = "a" ]
    3 -> 3 [ label = "a" ]
    0 -> 4 [ label = "b" ]
    1 -> 4 [ label = "a" ]
    3 -> 4 [ label = "b" ]
    4 -> 4 [ label = "a,b" ]
}
-->

<object type="image/svg+xml" data="/blog/2019/05/24/matrices-for-parsing/dfa.svg"></object>

ここで文字 `a` は遷移関数として
$$\delta(p, a) = \begin{cases}
    1 & (\text{if} ~ p = q_0) \\
    4 & (\text{if} ~ p = q_1) \\
    3 & (\text{if} ~ p = q_2) \\
    3 & (\text{if} ~ p = q_3) \\
    4 & (\text{if} ~ p = q_4) \\
\end{cases}$$
を持ち、その行列表現は
$$\dot{a} := \begin{pmatrix}
    0 & 0 & 0 & 0 & 0 \\
    1 & 0 & 0 & 0 & 0 \\
    0 & 0 & 1 & 1 & 0 \\
    0 & 0 & 0 & 0 & 0 \\
    0 & 1 & 0 & 0 & 1 \\
\end{pmatrix}$$ に対応する。

ただし、DFA のそれぞれの状態はベクトルに対応し、例えば初期状態
$$\dot{q_0} := \begin{pmatrix} 1 \\ 0 \\ 0 \\ 0 \\ 0 \end{pmatrix}$$
や状態
$$\dot{q_1} := \begin{pmatrix} 0 \\ 1 \\ 0 \\ 0 \\ 0 \end{pmatrix}$$
のようになる。
これを使えば $\dot{q_1} = \dot{a}\dot{q_0}$ などと計算できる。

### 応用

文字のそれぞれが行列として取り出せた。
これにより「この正規表現 $\gamma$ は 文字列 $w$ を $N$ 回繰り返したような文字列を受理するか？」のような問題に、単純な乗算と繰り返し二乗法を用いて $O(|Q|^3 \log N)$ の計算量で答えることができる。
DFA の状態数は (特定のまずいケースを踏まなければ) たいてい正規表現の文字列の長さと同程度に収まるので、$N$ が大きい場合にこれは十分高速である。

また「この正規表現 $\gamma$ に受理されるような文字列であって、長さが $N$ のものの数はいくつあるか？」のような問題にも、これらの行列を用いて答えることができる。
具体的には、それぞれの記号に対応する行列すべてを足し合せた ($\mathbb{N}$ 上の) 行列を $$\dot{\Sigma} := \sum _ {a \in \Sigma} \dot{a}$$ とする (記号の集合を表す文字 $\Sigma$ と総和を表す文字 $\sum$ が衝突していることに注意)。
これを用いてベクトル $$(\dot{\Sigma})^N \dot{q_0}$$ を求め、そのうち受理状態に対応する位置の要素を足し合わせれば (あるいは適切なベクトルとの内積を取れば) よい。
これも繰り返し二乗法を用いれば計算量は $O(|Q|^3 \log N)$ である。
これを実際に実装した例としては <https://github.com/kmyk/tinydfa/blob/26954cc68b8564dd3d780fa44c8d3b2b838a0584/test.cpp#L19-L41> がある (ただし、かなりを手を抜いていて行列を陽には用いておらず、計算量は $O(N \cdot |\Sigma| \cdot |Q|)$ である)。


## 数式

### 説明

単純な中置記法の数式の計算も行列を用いて扱うことができる。
ただし、括弧の深さが有界であるという仮定が重要である。

まず、減法も除法も括弧もなく、加法 $+$ と乗法 $\ast$ だけを扱うと仮定して話をする。
文法を BNF で書くと以下のようになる。

```
<expr> := <term> | <term> '+' <expr>
<term> := <number> | <number> '*' <term>
<number> := <digit> | <digit> <number>
<digit> := '0' | '1' | '2' | '3' | '4' | '5' | '6' | '7' | '8' | '9'
```

つまり数式の全体は $$n _ {1,1} \ast n _ {1,2} \ast \dots \ast n _ {1,w_1} + n _ {2,1} \ast n _ {2,2} \ast \dots \ast n _ {2,w_2} + \dots + n _ {h,1} \ast n _ {h,2} \ast \dots \ast n _ {h,w_h}$$ という形をしている。
$t_y = n _ {y,1} \ast n _ {y,2} \ast \dots \ast n _ {y,w_y}$ と書くことにする。
文字列を前から順に見ていきながら計算することを考えれば、現在の項の手前までの総和 $a := t_1 + t_2 + \dots + t _ {y - 1}$ と、(現在の項の中での) 現在の数の手前までの総積 $b := n _ {y,1} \ast n _ {y,2} \ast \dots \ast n _ {y,x - 1}$ を管理すればよい。
このようにして、ベクトル $$\begin{pmatrix} a \\ b \end{pmatrix}$$ を行列で操作したい気持ちになる。

丁寧な前処理が可能でかつそれをすればベクトル $$\begin{pmatrix} a \\ b \end{pmatrix}$$ で十分であるが、まだ不足である。
さらに、それぞれの数 $n _ {y,x}$ は数字の列 $d _ {y,x,1} d _ {y,x,2} \dots d _ {y,x,l _ {y,x}}$ であるが、これは現在見ている数字の手前までの結果 $c := d _ {y,x,1} d _ {y,x,2} \dots d _ {y,x,z - 1}$ を持っておけば同様の形で計算ができる。
この $c$ をその用途に従い $bc$ として加え、さらに形式的に整数 $1$ を加えたベクトル $$\begin{pmatrix} a \\ b \\ bc \\ 1 \end{pmatrix}$$ を扱うと上手くいく。
このときそれぞれの文字に対応する行列は、以下のような線形操作をするものである。

-   加法 `+` に対して $$\begin{pmatrix}a + bc \\ +1 \\ 0 \\ 1 \end{pmatrix} = \begin{pmatrix}1 & 0 & 1 & 0 \\ 0 & 0 & 0 & +1 \\ 0 & 0 & 0 & 0 \\ 0 & 0 & 0 & 1 \end{pmatrix} \begin{pmatrix}a \\ b \\ bc \\ 1 \end{pmatrix}$$
-   乗法 `*` に対して $$\begin{pmatrix}a \\ bc \\ 0 \\ 1 \end{pmatrix} = \begin{pmatrix}1 & 0 & 0 & 0 \\ 0 & 0 & 1 & 0 \\ 0 & 0 & 0 & 0 \\ 0 & 0 & 0 & 1 \end{pmatrix} \begin{pmatrix}a \\ b \\ bc \\ 1 \end{pmatrix}$$
-   数字 `d` に対して $$\begin{pmatrix}a \\ b \\ b \cdot (10c+\mathrm{d}) \\ 1 \end{pmatrix} = \begin{pmatrix}1 & 0 & 0 & 0 \\ 0 & 1 & 0 & 0 \\ 0 & \mathrm{d} & 10 & 0 \\ 0 & 0 & 0 & 1 \end{pmatrix} \begin{pmatrix}a \\ b \\ bc \\ 1 \end{pmatrix}$$
-   入力の末尾で、答えを得るために $$a + bc = \begin{pmatrix}1 & 0 & 1 & 0 \end{pmatrix} \begin{pmatrix}a \\ b \\ bc \\ 1 \end{pmatrix}$$

これが基本形となる。

### 拡張

<small>
注意: 除法や括弧については、実際に実装をしての検証作業はしていません。何か漏れがあるかも
</small>

ここに減法 $-$ を加えるには、そのまま、減法 `-` に対しての線形操作 $$\begin{pmatrix}a + bc \\ -1 \\ 0 \\ 1 \end{pmatrix} = \begin{pmatrix}1 & 0 & 1 & 0 \\ 0 & 0 & 0 & -1 \\ 0 & 0 & 0 & 0 \\ 0 & 0 & 0 & 1 \end{pmatrix} \begin{pmatrix}a \\ b \\ bc \\ 1 \end{pmatrix}$$ を使えばよい。

ここに除法 $/$ を加えるにはベクトルに対する大幅な修正が必要となる。
まず `*` と `/` の区別のために、条件分岐用の変数 $p$ を考える。
数字 $\mathrm{d}$ を見ていく際に、現在の位置が `*` に用いられる範囲のとき $p = 1$ に、現在の位置が `/` に用いられる範囲のとき $p = 0$ になるようにすればよい。
次に、変数 $bc$ だけでなく $bc^{-1}$ も管理したい。
だとすると変数 $c, c^{-1}, bc, bc^{-1}$ などと定数 $d$ から $b(10c + d)^{-1}$ を作ることができる必要がある。
しかし除法 $p / q$ は行列の外に出るまで計算することは不可能である。
これは行列の要素の意味をすこしずらし、行列の中で数を有理数に展開した $p, q$ という形で持つことで解決できる。
$c$ は常に整数であることに注意して、ベクトルは $$\begin{pmatrix}
    a_n \\ a_d \\ pb_n \\ pb_d \\ pb_nc \\ (1-p)b_n \\ (1-p)b_d \\ (1-p)b_dc \\ 1
\end{pmatrix}$$ となる。
除法 `/` に対しての線形操作は条件変数 $p$ を設定するだけなので $$\begin{pmatrix}
    a_n \\ a_d \\ 0 \\ 0 \\ 0 \\ pb_nc + (1-p)b_n \\ pb_d + (1-p)b_dc \\ 0 \\ 1
\end{pmatrix} = \begin{pmatrix}
    1 & 0 & 0 & 0 & 0 & 0 & 0 & 0 & 0 \\
    0 & 1 & 0 & 0 & 0 & 0 & 0 & 0 & 0 \\
    0 & 0 & 0 & 0 & 0 & 0 & 0 & 0 & 0 \\
    0 & 0 & 0 & 0 & 0 & 0 & 0 & 0 & 0 \\
    0 & 0 & 0 & 0 & 0 & 0 & 0 & 0 & 0 \\
    0 & 0 & 0 & 0 & 1 & 1 & 0 & 0 & 0 \\
    0 & 0 & 0 & 1 & 0 & 0 & 0 & 1 & 0 \\
    0 & 0 & 0 & 0 & 0 & 0 & 0 & 0 & 0 \\
    0 & 0 & 0 & 0 & 0 & 0 & 0 & 0 & 1 \\
\end{pmatrix} \begin{pmatrix}
    a_n \\ a_d \\ pb_n \\ pb_d \\ pb_nc \\ (1-p)b_n \\ (1-p)b_d \\ (1-p)b_dc \\ 1
\end{pmatrix}$$ とする。
もちろん他の行列にも修正が必要である。数字 `d` に対応する行列が最も難しくて $$\begin{pmatrix}
    a_n \\ a_d \\ pb_n \\ pb_d\\ pb_n \cdot (10c + \mathrm{d}) \\ (1-p)b_n \\ (1-p)n_d \\ (1-p)b_d \cdot (10c + \mathrm{d}) \\ 1
\end{pmatrix} = \begin{pmatrix}
    1 & 0 & 0 & 0 & 0 & 0 & 0 & 0 & 0 \\
    0 & 1 & 0 & 0 & 0 & 0 & 0 & 0 & 0 \\
    0 & 0 & 1 & 0 & 0 & 0 & 0 & 0 & 0 \\
    0 & 0 & 0 & 1 & 0 & 0 & 0 & 0 & 0 \\
    0 & 0 & \mathrm{d} & 0 & 10 & 0 & 0 & 0 & 0 \\
    0 & 0 & 0 & 0 & 0 & 1 & 0 & 0 & 0 \\
    0 & 0 & 0 & 0 & 0 & 0 & 1 & 0 & 0 \\
    0 & 0 & 0 & 0 & 0 & 0 & \mathrm{d} & 10 & 0 \\
    0 & 0 & 0 & 0 & 0 & 0 & 0 & 0 & 1 \\
\end{pmatrix} \begin{pmatrix}
    a_n \\ a_d \\ pb_n \\ pb_d \\ pb_nc \\ (1-p)b_n \\ (1-p)b_d \\ (1-p)b_dc \\ 1
\end{pmatrix}$$ となる。
他も同様に拡張することで実現可能である。
実用上は、数字でなく数がひとつのトークンになるように前処理をするなどをするとよい。

有限個の括弧を加えるのは、ベクトルに対して簡単な修正で済む。
$1$ 重から $2$ 重以上への拡張は自然にできるため、高々 $1$ 重の括弧を加える場合のみを説明する。
途中経過 $a, b$ を別の場所に退避させるようにすればよく、
ベクトル $$\begin{pmatrix} a \\ b \\ bc \\ 1 \end{pmatrix}$$ の代わりにベクトル $$\begin{pmatrix}
    a_1 \\ b_1 \\ a_0 \\ b_0 \\ b_0c \\ 1
\end{pmatrix}$$ を用いる。
初期状態となるベクトルには $$\begin{pmatrix}
    a_1 \\ b_1 \\ a_0 \\ b_0 \\ b_0c \\ 1
\end{pmatrix} = \begin{pmatrix}
    0 \\ 1 \\ 0 \\ 1 \\ 0 \\ 1
\end{pmatrix}$$ を用いる。
開き括弧 `(` に対して、 $a_1 = 0$ かつ $b_1 = 1$ であることを前提として $$\begin{pmatrix}
    a_0 \\ b_0c_0 \\ 0 \\ b_0 \\ 0 \\ 1
\end{pmatrix} = \begin{pmatrix}
    0 & 0 & 1 & 0 & 0 & 0 \\
    0 & 0 & 0 & 0 & 1 & 0 \\
    0 & 0 & 0 & 0 & 0 & 0 \\
    0 & 0 & 0 & 1 & 0 & 0 \\
    0 & 0 & 0 & 0 & 0 & 0 \\
    0 & 0 & 0 & 0 & 0 & 1 \\
\end{pmatrix} \begin{pmatrix}
    0 \\ 1 \\ a_0 \\ b_0 \\ b_0c \\ 1
\end{pmatrix}$$ とし、
閉じ括弧 `)` に対しては $$\begin{pmatrix}
    0 \\ 1 \\ a_1 \\ a_0 + b_0c \\ 0 \\ 1
\end{pmatrix} = \begin{pmatrix}
    0 & 0 & 0 & 0 & 0 & 0 \\
    0 & 0 & 0 & 0 & 0 & 1 \\
    1 & 0 & 0 & 0 & 0 & 0 \\
    0 & 0 & 1 & 0 & 1 & 0 \\
    0 & 0 & 0 & 0 & 0 & 0 \\
    0 & 0 & 0 & 0 & 0 & 1 \\
\end{pmatrix} \begin{pmatrix}
    a_1 \\ b_1 \\ a_0 \\ b_0 \\ b_0c \\ 1
\end{pmatrix}$$ とする。
括弧の中では括弧の外側に由来する定数倍 $b_1$ が付くことに注意する。
たとえば加法 `+` に対しても $$\begin{pmatrix}
    a_1 \\ b_1 \\ a_0 + b_0c \\ b_1 \\ 0 \\ 1
\end{pmatrix} = \begin{pmatrix}
    1 & 0 & 0 & 0 & 0 & 0 \\
    0 & 1 & 0 & 0 & 0 & 0 \\
    0 & 0 & 1 & 0 & 1 & 0 \\
    0 & 1 & 0 & 0 & 0 & 0 \\
    0 & 0 & 0 & 0 & 0 & 0 \\
    0 & 0 & 0 & 0 & 0 & 1 \\
\end{pmatrix} \begin{pmatrix}
    a_1 \\ b_1 \\ a_0 \\ b_0 \\ b_0c \\ 1
\end{pmatrix}$$ となる。

### 評価

行列は一般に変数倍を扱えない。
関数 $f(x) = x^2$ や $g(x, y) = xy$ は一般に線形でない。
しかし今回の変数 $c$ は実際には $c = d _ {y,x,1} d _ {y,x,2} \dots d _ {y,x,l _ {y,x}}$ と組み立てられる定数であるので、このようなことが実現できている。

同様に、行列は一般に除算を扱えない。
関数 $f(x) = x^{-1}$ は一般に線形でない。
今回の変数 $c$ は実質的な定数であるので、$c^{-1}$ をかけるという操作は定数倍の延長として実現できる。

(有限の) 行列は非有界な数の状態を扱えない。
これは行列の大きさが固定されているため。
とはいえ入力に対し十分大きな行列を用意すれば問題は起きない。


### 利用例

[JAG Practice Contest for ACM-ICPC Asia Regional 2016: J - Compressed Formula](https://atcoder.jp/contests/jag2016autumn/tasks/icpc2016autumn_j) は、規則的な文字列 $s_1^{r_1} s_2^{r_2} \dots s_N^{r_N}$ として与えられる数式の値を計算する問題です。
行列として表現し繰り返し二乗法を用いることで解けます。
括弧の高さに制限がない場合も、面倒な処理を丁寧にやれば計算できます。
たとえば $s_1^{r_1} s_2^{r_2}$ という形であって $s_1, s_2$ がそれぞれ括弧の深さを $+n_1, -n_2$ するとき、バランスするように $\dots s_1^{n_2} (s_1^{n_2} (s_1^{n_2}s_2^{n_1}) s_2^{n_1}) s_2^{n_1} \dots$ と見て内側から順番に計算していくことができ、これもまた行列で扱えます。

[yukicoder No.619 CardShuffle](https://yukicoder.me/problems/no/619) や [いろはちゃんコンテスト Day2: J - ライ麦畑で待ちながら](https://atcoder.jp/contests/iroha2019-day2/tasks/iroha2019_day2_j) は括弧のない数式が文字列 $s$ として与えられ、その全体や部分文字列として得られる数式を計算する問題です。
さらに、文字列 $s$ の文字を置き換える操作への対応する必要があります。
これは行列を乗せたセグメント木を用いることで解けます。

除法や括弧が扱えるという事実はそれ自体はあまり実用的なものではなく、他の場面での行列芸の応用のための例と見るべきだろう。
