---
category: blog
layout: post
date: 2020-03-07T00:00:00+09:00
tags: [ "competitive", "minimum-cat", "propositional-logic" ]
---

# 最小カット問題と充足最大化問題

<div hidden>
$$
\newcommand{\bigdoublewedge}{
  \mathop{
    \mathchoice{\bigwedge\mkern-15mu\bigwedge}
               {\bigwedge\mkern-12.5mu\bigwedge}
               {\bigwedge\mkern-12.5mu\bigwedge}
               {\bigwedge\mkern-11mu\bigwedge}
    }
}
\newcommand{\bigdoublevee}{
  \mathop{
    \mathchoice{\bigvee\mkern-15mu\bigvee}
               {\bigvee\mkern-12.5mu\bigvee}
               {\bigvee\mkern-12.5mu\bigvee}
               {\bigvee\mkern-11mu\bigvee}
    }
}
$$
</div>

## はじめに

この記事では、最小カットを用いて次の形の重み付き充足最大化問題が解けることを説明する:

*特定の形の論理式からなるある集合 $$T \subseteq \left\lbrace \bigdoublevee_i p_i \to \bigdoublewedge_j q_j ~\middle\vert~ (p_1, p_2, \dots, p_n), (q_1, q_2, \dots, q_m) \text{は論理式の (非空とは限らない) 列} \right\rbrace$$ とそれに対する正の重み $c : T \to \mathbb{R} _ {\ge 0}$ が与えられる。
このとき、理論として無矛盾な部分集合 $S \subseteq T$ であって $\sum _ {\varphi \in S} c(\varphi)$ が最大となるような $S$ をひとつ求めよ。また、そのような $S$ を妥当とする真理値割り当てをひとつ求めよ。*

つまり、特定の形の命題論理式 $\varphi$ に対しての「$\varphi$ が真でなければ $c(\varphi) \ge 0$ のペナルティを受ける」の形の制約がたくさん与えられたとき、ペナルティ最小となるような真理値割り当てを求めることができる。これは「燃やす埋める問題」や Project Selection Problem と呼ばれるものと等価であるが、より理解しやすい形で整理されている点にうれしさがある。

フローの基本や命題論理の基本についての説明は省略する。必要なら適当な入門書 ([プログラミングコンテストチャレンジブック](https://www.amazon.co.jp/dp/4839941068) や [情報科学における論理](https://www.amazon.co.jp/dp/45356081480) など) を読んでほしい。


## 基本方針

最小カット問題は、グラフの頂点を $2$ 色で彩色する以下のような問題と同値であることが知られている。

*ネットワーク $N = (V, E, c, s, t)$ が与えられる。重みは全て正とし、全ての頂点 $v \in V$ はそれを通る $s-t$ 有向路を持つとする。頂点を $2$ 彩色したい。色は赤と青とし、頂点 $s$ は必ず赤、頂点 $t$ は必ず青とする。有向辺 $e = (u,v) \in E$ があるとき、頂点 $u$ が赤かつ頂点 $v$ が青で塗られていれば、$c(e) \in \mathbb{R} \cup \lbrace \infty \rbrace$ だけペナルティをうけるとする。ペナルティの最小値はいくらか。*

この $2$ 彩色の赤と青を真偽値の真と偽だと解釈するのが中心となるアイデアである。
まず、与えられた論理式の集合 $T$ 中で用いられている命題変数をすべて列挙し $V_0$ とする。
それぞれの命題変数 $p \in V_0$ に対応する頂点 $p$ を作り、これが赤で塗られるなら $p$ が真であり、これが青で塗られるなら $p$ が偽であると解釈する。
そして $\varphi \in T$ の重みが $c(\varphi)$ であるとは、$\varphi$ が真でなければ $c(\varphi) \ge 0$ のペナルティを受けることを意味する。
また、ネットワークの始点は恒真式 $\top$ に対応し終点は矛盾 $\bot$ に対応するとする。
この解釈に沿うように $T$ 中の論理式に対応する頂点や辺を追加すると、その $\top-\bot$ 最小カットの大きさが $T$ の無矛盾な部分集合の最大の重みと等しいグラフが作れる。


## 構成法

集合 $T$ で表現される制約を反映するには、具体的にどのようにグラフを作ればよいだろうか？
論理式 $\varphi = (\bigdoublevee_i p_i \to \bigdoublewedge_j q_j) \in T$ ごとに処理を行う。
まず、ふたつの頂点 $\bigdoublevee_i p_i$ と $\bigdoublewedge_j q_j$ を作り、それぞれ関連する命題変数との間に重み $\infty$ の辺を張る。
すでに同じ論理式に対応する頂点があるならば、それは再利用するものとする。
そしてこのふたつの間に、以下の図 ($n = m = 4$ のとき) のように重み $c(\varphi)$ の辺を張る。

![論理式 $\bigdoublevee_i p_i \to \bigdoublewedge_j q_j$ についてのグラフ](/blog/2020/03/07/minimum-cut-and-maximum-satisfiability/sum-implies-product.svg)

ただし、列 $(p_1, p_2, \dots, p_n)$ や $(q_1, q_2, \dots, q_m)$ が空のときは論理積の単位元 $\top$ と論理和の単位元 $\bot$ が用いられることに注意せよ。
これはネットワークの始点 $\top$ や終点 $\bot$ と同一の頂点であるとする。
図で書くと以下のようになる。

![論理式 $\lnot \bigdoublevee_i p_i$ についてのグラフ](/blog/2020/03/07/minimum-cut-and-maximum-satisfiability/not-sum.svg)
![論理式 $\bigdoublewedge_j q_j$ についてのグラフ](/blog/2020/03/07/minimum-cut-and-maximum-satisfiability/product.svg)

このようにして構成されたグラフは所望の性質を満たす。

## 例

ここまでは一般的な形で書いたが、ここからはより具体的なケースでの例を見ていく。

### 始点や終点との辺: $p$ と $\lnot p$

命題変数 $p$ に対し「$p$ が真でなければ $c(p)$ のペナルティを受ける」ことを表現するには、始点 $\top$ から $p$ へ重み $c(p)$ の辺を張ればよい。
また「$\lnot p$ が真でなければ $c(\lnot p)$ のペナルティを受ける」ことを表現するには、$p$ から終点 $p$ へ重み $c(\lnot p)$ の辺を張ればよい。
グラフはまとめて書くと以下のようになる。

![論理式 $p, \lnot p$ についてのグラフ](/blog/2020/03/07/minimum-cut-and-maximum-satisfiability/top-a-bot.svg)

### 省略記法

これ以降では、簡単のため $\top$ や $\bot$ の頂点は省略する。
たとえば上記の $\top \to p$ と $p \to \bot$ のグラフは次のように書かれる。

![論理式 $p, \lnot p$ についての省略して書かれたグラフ](/blog/2020/03/07/minimum-cut-and-maximum-satisfiability/just-a.svg)

### ふたつの頂点の間の辺: $p \to q$ と $p \leftrightarrow q$

始点や終点以外の頂点 $p, q$ を結ぶ辺を見ていこう。
「含意 $p \to q$ が真でなければ $c(p \to q)$ のペナルティを受ける」ことを表現するには、頂点 $p$ から頂点 $q$ へ重み $c(p \to q)$ の辺を張ればよい。
図で書くと以下のようになる。

![論理式 $p \to q$ についてのグラフ](/blog/2020/03/07/minimum-cut-and-maximum-satisfiability/a-implies-b.svg)

ここで $\hat{c} = c(p \to q) = c(q \to p)$ にすると、これは $c(p \leftrightarrow q) = \hat{c}$ だと思える。
つまり「同値 $p \leftrightarrow q$ が真でなければ $c(p \to q)$ のペナルティを受ける」ことが表現できる。
図にするときは以下のように書くとよいだろう。

![論理式 $p \leftrightarrow q$ についてのグラフ](/blog/2020/03/07/minimum-cut-and-maximum-satisfiability/a-iff-b.svg)

### 仮想的な頂点: $p \wedge q$ と $p \vee q$

最後は論理積と論理和である。
命題変数 $p, q$ に対する論理積 $p \wedge q$ と論理和 $p \vee q$ についての「$p \wedge q$ が真でなければ $c(p \wedge q)$ のペナルティを受ける」「$\lnot (p \lor q)$ が真でなければ $c(\lnot (p \lor q))$ のペナルティを受ける」という制約は、次のグラフのようにして表現される。

![論理式 $p \wedge q, p \vee q$ についてのグラフ](/blog/2020/03/07/minimum-cut-and-maximum-satisfiability/diamond.svg)

これが実際にどう機能するかについても眺めておこう。
ふたつの命題変数 $p, q$ の真偽に従って $4$ 通りのカットが考えられる。

まず、$p$ が真かつ $q$ が偽のときのカットは次の図のようになる。
$p$ が真かつ $q$ が偽であるならば、このような形のカットしかありえないという事実に注意してほしい。
そして、論理式 $\lnot p, q, p \wedge q, \lnot (p \vee q)$ はどれも偽なので、これらの制約に対応する辺がカットされている。
ただし、頂点 $p \wedge q$ から頂点 $p$ への重み $\infty$ の辺などは偽の側から正の側への辺であるのでカットされる必要はない。

![論理式 $p \wedge \lnot q$ の場合のカット](/blog/2020/03/07/minimum-cut-and-maximum-satisfiability/a-and-not-b.svg)

次に、$p$ が偽かつ $q$ が偽のときのカットは次の図のようになる。
論理式 $ p, q, p \wedge q$ が偽なので、これらの制約に対応する辺がカットされる。

![論理式 $\lnot p \wedge \lnot q$ の場合のカット](/blog/2020/03/07/minimum-cut-and-maximum-satisfiability/not-a-and-not-b.svg)

同様に、$p$ が偽かつ $q$ が真のときのカットは次の図のようになる。

![論理式 $\lnot p \wedge q$ の場合のカット](/blog/2020/03/07/minimum-cut-and-maximum-satisfiability/not-a-and-b.svg)

最後に、$p$ が真かつ $q$ が真のときのカットは次の図のようになる。

![論理式 $p \wedge q$ の場合のカット](/blog/2020/03/07/minimum-cut-and-maximum-satisfiability/a-and-b.svg)


## おまけ: 実用上の注意

この節の内容は Project Selection Problem として表現したときと共通の議論であり、論理式を使うことと関連は薄い。
しかし実用上重要なので紹介しておく。

### 否定を取るかとらないか

同じ種類の変数 $p_i$ だけが存在する場合は、$p_i$ と $\lnot p_i$ は等価である。
それぞれの $i$ について「$a_i$ を使うか、使わないか」の割り当てを考える場合に、命題変数 $p_i$ の意味として「$a_i$ を使う」を選んでも「$a_i$ を使わない」を選んでも差はないだろう。

複数の種類の変数 $p_i$ や $q_j$ が存在する場合はそうでない。
たとえば $2$ 種類の物 $a_1, a_2, \dots, a_m, b_1, b_2, \dots, b_n$ があり、いくつかの $i, j$ の組に対し「$a_j$ を使うならば $b_j$ を使ってはいけない」という制約がある状況を考えよう。
このとき、命題変数 $p_i$ の意味として「$a_i$ を使う」を選び、命題変数 $q_j$ の意味として「$b_j$ を使う」を選ぶと「$p_i \wedge \lnot q_j$ が真でなければ $\infty$ のペナルティを受ける」という制約が必要になるが、これを表現することはできない。
命題変数 $q_j$ の意味として「$b_j$ を使わない」を選べば「$p_i \to q_j$ が真でなければ $\infty$ のペナルティを受ける」という制約になり、処理可能である。

### $3$ 値以上の場合

論理式は真と偽の $2$ 値しか扱えないため、$3$ つ以上選択肢のある状況を考えたい場合には工夫が必要である。
これには、各選択肢を表現するための命題変数の間にうまく線形な含意関係を入れるとよい。

まず、明らかに順序がある場合の例を見よう。
自然数 $x_1, x_2, \dots, x_n$ のそれぞれに $1, 2, 3, 4, 5 \in \mathbb{N}$ のいずれかを割り当てるとしよう。
この場合、命題変数 $p_i$ の意味として「$x_i \le i$ が成り立つ」を選択し「$p_i \to p _ {i+1}$ が真でなければ $\infty$ のペナルティを受ける」を加えるとよいだろう。
$p_i \leftrightarrow x_i \le i$ ($i \in \lbrace 1, 2, 3, 4 \rbrace$) のときのグラフの様子は次のようになる。

![](/blog/2020/03/07/minimum-cut-and-maximum-satisfiability/line.svg)

ただし、$2$ 値のときと同様に否定を取ると状況が変わることがある。$p_i$ の意味として「$x_i \gt i$ が成り立つ」も試しておくべきだろう。
$p_i \leftrightarrow x_i \le i$ ($i \in \lbrace 1, 2, 3, 4 \rbrace$) のときのグラフの様子は次のようになる。

![](/blog/2020/03/07/minimum-cut-and-maximum-satisfiability/line-reversed.svg)

次に、人工的な順序を探す必要のある場合の例を見ていこう。
物 $a_1, a_2, \dots, a_n$ のそれぞれに「燃やす」「埋める」「何もしない」の $3$ 通りのうちいずれかを割り当てるとしよう。
これにも線形な含意関係を入れることができる。
「$a_i$ を燃やす」「$a_i$ を埋める」「$a_i$ について何もしない」をそれぞれ $P_i, Q_i, R_i$ と書くとしよう。
$P_i, Q_i, R_i$ はいずれかふたつ以上が同時に成り立つことがない。
ここに $P_i \to P_i \vee Q_i$ および $P_i \vee Q_i \to P_i \vee Q_i \vee R_i$ という機械的な順序が入れられる。
そして命題変数を $p_i \leftrightarrow P_i$ 「$a_i$ を燃やす」と $q_i \leftrightarrow P_i \vee Q_i$ 「$a_i$ を燃やすか $a_i$ を埋める」で定義し、制約「$p_i \to q_i$ が真でないならば $\infty$ のペナルティを受ける」を加えればよい。

もちろん順序も適切なものを選ぶ必要があるだろう。
たとえば「$a_i$ を燃やしたならば $a_j$ を埋めてはならない」場合を考えてみよう。
つまり $P_i \to \lnot Q_j$ が真であればよい。
これをうまく表現できるような $p_i, q_j$ を選びたい。
ここで $\lnot Q_j \leftrightarrow P_j \vee R_j$ であることに気付けば、$p_i \leftrightarrow P_i$ 「$a_i$ を燃やす」と $q_i \leftrightarrow P_i \vee R_i$ 「$a_i$ を燃やすか $a_i$ は何もしない」で定義するのがよさそうだと分かる。
$p_i \to q_j$ は「$a_i$ を燃やしたならば $a_j$ を埋めてはならない」になる。
図にすると次のようになる。

![](/blog/2020/03/07/minimum-cut-and-maximum-satisfiability/three.svg)

## まとめ

最小カットを用いてある形の重み付き充足最大化問題が解けることを見た。
特定の形の命題論理式 $\varphi$ に対しての「$\varphi$ が真でなければ $c(\varphi) \ge 0$ のペナルティを受ける」の形の制約がたくさん与えられたとき、最小カットを用いて、ペナルティ最小となるような真理値割り当てを求めることができる。

特に、命題変数 $p, q$ に対し次の制約が書ける。

-   「$p$ が真でなければ $c \ge 0$ のペナルティを受ける」
-   「$\lnot p$ が真でなければ $c \ge 0$ のペナルティを受ける」
-   「$p \to q$ が真でなければ $c \ge 0$ のペナルティを受ける」
-   「$p \wedge q$ が真でなければ $c \ge 0$ のペナルティを受ける」
-   「$\lnot (p \vee q)$ が真でなければ $c \ge 0$ のペナルティを受ける」

より一般に、命題変数 $p_1, p_2, \dots, p_n, q_1, q_2, \dots, q_m$ に対し、次が書ける:

-   「$\bigdoublevee_i p_i$ が真でなければ $c \ge 0$ のペナルティを受ける」
-   「$\lnot \bigdoublewedge_j q_j$ が真でなければ $c \ge 0$ のペナルティを受ける」
-   「$\bigdoublevee_i p_i \to \bigdoublewedge_j q_j$ が真でなければ $c \ge 0$ のペナルティを受ける」

## 関連記事

-   [最小カットを使って「燃やす埋める問題」を解く - SlideShare, @nico_shindannin](https://www.slideshare.net/shindannin/project-selection-problem)
    -   「燃やす埋める問題」という概念は、おそらくこの記事で始めて紹介された。
-   [最小カットを使って「燃やす埋める」問題を解くスライドのフォロー - じじいのプログラミング](http://shindannin.hatenadiary.com/entry/2017/11/15/043009)
-   [最小カットについて - よすぽの日記](https://yosupo.hatenablog.com/entry/2015/03/31/134336)
    -   最小カット問題はグラフの $2$ 彩色だと思うとよいことが説明されている。
-   [『燃やす埋める』と『ProjectSelectionProblem』 - とこはるのまとめ](http://tokoharuland.hateblo.jp/entry/2017/11/12/234636)
    -   「燃やす埋める問題」という語を使うのをやめて Project Selection Problem を考えるべきだと主張されている。
-   [Project Selection (燃やす埋める) 周りの話についてもう少し考えた - とこはるのまとめ](http://tokoharuland.hateblo.jp/entry/2017/12/25/000003)
-   [最小カットとProject Selection Problemのまとめ - うさぎ小屋](https://kimiyuki.net/blog/2017/12/05/minimum-cut-and-project-selection-problem/)
    -   私が過去に最小カット問題と命題論理の関係を独自に調べた結果をまとめたもの。今回の記事はこの記事を元に図や考察を足して書き直したものである。
