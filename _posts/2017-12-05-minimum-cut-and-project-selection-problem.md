---
category: blog
layout: post
date: "2017-12-05T19:57:47+09:00"
tags: [ "competitive", "min-cut", "max-flow", "project-selection-problem" ]
---

# 最小カットとProject Selection Problemのまとめ

## 前書き

先日「Project Selection Problem」が流行った。
それらを見ていたら最小カットについて面白いことが言えそうだった(まだほとんど分かってないのでこの記事では書かない書けないが)ので、自分の理解のために整理した。
切り分けのため新規な話題は意図的に削ってある。
以下の記事たちの焼き直しであるためそれらが理解できていればこの記事を読む必要はないだろう。

-   [最小カットについて - よすぽの日記](http://yosupo.hatenablog.com/entry/2015/03/31/134336)
-   [『燃やす埋める』と『ProjectSelectionProblem』 - とこはるのまとめ](http://tokoharuland.hateblo.jp/entry/2017/11/12/234636)
-   [続：『燃やす埋める』と『ProjectSelectionProblem』 - とこはるのまとめ](http://tokoharuland.hateblo.jp/entry/2017/11/13/220607)
-   [最小カットを使って「燃やす埋める問題」を解く](https://www.slideshare.net/shindannin/project-selection-problem)
-   [最小カットを使って「燃やす埋める」問題を解くスライドのフォロー - じじいのプログラミング](http://shindannin.hatenadiary.com/entry/2017/11/15/043009)
-   [ネットワークフロー入門](http://hos.ac/slides/20150319_flow.pdf)

## 最小カットの定義と同値な問題

次の$3$つは同値である。

### 最小カット問題

ネットワーク$N = (V, E, c, S, T)$が与えられる。
ただしネットワークとは、有限の有向グラフ$G = (V, E)$で辺の非負な重み$c : E \to \mathcal{R} \cup \{ \infty \}$と異なる頂点$S, T \in V$を持つものとする。
$S \to T$有向pathがなくなるように辺を削除するときの、削除される辺の重みの最小値を答えよ。

### 最大流問題

ネットワーク$N = (V, E, c, S, T)$が与えられる。
フローの容量の最大値を求めよ。
ただしネットワーク$N$のフローとは、関数$f : E \to \mathcal{R} \cup \{ \infty \}$で流量制約$0 \le f(e) \le c(e)$と流量保存則$\forall v \in V. v \ne S, T \to \sum\_{(u, v) \in E} f(u, v) = \sum\_{(v, w) \in E} f(v, w)$を満たすもの。
その容量とは$\sum\_{(S, v) \in E} f(S, v) = \sum\_{(v, T) \in E} f(v, T)$の値。

同値性は最大流最小カット定理として知られる。
アルゴリズムはたくさんあり、フローの容量$F$に対し$O(EF)$のFord-Fulkersonのアルゴリズム、$O(VE^2)$のEdmonds-Karpのアルゴリズム、$O(V^2E)$のDinicのアルゴリズムが有名。[Wikipedia](https://en.wikipedia.org/wiki/Maximum_flow_problem)によるとJames B Orlin's + KRT (King, Rao, Tarjan)'s algorithmなら$O(VE)$で解けるらしい。
ただしネットワークの重みに負を許した場合はNP困難となる。

### 特殊な形の2彩色問題

ネットワーク$N = (V, E, c, S, T)$が与えられる。
重みは全て正とし、全ての頂点$v \in V$はそれを通る$s-t$有向路を持つとする。
頂点を$2$彩色したい。
色は赤と青とし、頂点$S$は必ず赤、頂点$T$は必ず青とする。
有向辺$e = (u, v) \in E$があるとき、頂点$u$が赤かつ頂点$v$が青で塗られていれば、$c(e)$だけペナルティをうけるとする。
ペナルティの最小値はいくらか。

最小カットの簡単な言い換えとなる。
出典は以下:

<http://yosupo.hatenablog.com/entry/2015/03/31/134336>

<blockquote class="twitter-tweet" data-lang="en"><p lang="ja" dir="ltr">ARCに最小カットを出したら最小カットが結構話題になったっぽいんですが、最小カット問題を「辺を選ぶ」問題、つまり辺をいくつか選んでS, T間のパスを消す問題、と認識してしまうと、かなり(プロコンにおいては)損だと思います</p>&mdash; W521 (@yosupot) <a href="https://twitter.com/yosupot/status/930452292326735872?ref_src=twsrc%5Etfw">November 14, 2017</a></blockquote>
<script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

<blockquote class="twitter-tweet" data-lang="en"><p lang="ja" dir="ltr">「頂点を選ぶ」、つまり頂点をS側とT側に分割する問題だと思ってやっていくと、きっとARC EもProject Selectionも&quot;自明&quot;、&quot;やるだけ&quot;になると思います</p>&mdash; W521 (@yosupot) <a href="https://twitter.com/yosupot/status/930452601245614081?ref_src=twsrc%5Etfw">November 14, 2017</a></blockquote>
<script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

<blockquote class="twitter-tweet" data-lang="en"><p lang="ja" dir="ltr">そもそも最大流問題が辺に値を割り振る問題なんだから、双対は頂点に関する問題でないとおかしくない？</p>&mdash; W521 (@yosupot) <a href="https://twitter.com/yosupot/status/930452873233571840?ref_src=twsrc%5Etfw">November 14, 2017</a></blockquote>
<script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>


## 応用先となる典型的な問題

### Project Selection Problem

<http://tokoharu.github.io/tokoharupage/docs/formularization.pdf> p7 から引用

>   $N$個の要素がある．最初どの頂点も集合$B$に属しているが，これを集合$A$に移すことで利益を最大化したい．
>   要素$i$が$A$に属する時には利得$p\_i$を得るという情報が与えられる．
>   さらに$3$つ組の列$(x\_j, y\_j, z\_j)$が与えられ，これは$x\_j$が$A$に属し，かつ$y\_j$が$B$に属していた時に$z\_j(\ge 0)$だけ損失をすることを意味する．
>   得られる利得の最大値を答えよ．

### 燃やす埋める問題

$N$個のゴミがある。それぞれのゴミは「燃やす」か「土に埋める」必要がある。
それぞれのゴミ$x$について、「燃やす」と$f(x)$円「土に埋める」と$g(x)$円かかる。
さらに次の形の制約がいくつか与えられる: ゴミ$x$を「燃やし」かつゴミ$y$を「土に埋める」と罰金$h(x, y)$円かかる。
全てのゴミを処理するための費用はいくらか。

競プロ界隈のみ使われる名称であるので、Project Selection Problemを代わりに利用することが提唱されている(<http://tokoharuland.hateblo.jp/entry/2017/11/12/234636>)。

## 最小カットで解ける問題について

どのような問題なら最小カットで解けるか考えたい。
頂点の$2$彩色は最小カットと同値であるため、これに帰着できる問題が必要十分である。

よって、彩色への帰着のさせかたについて考える。
問題の定義からただちに対応できる制約は次のみである:

-   頂点$u$が赤かつ頂点$v$が青で塗られていれば$c \ge 0$のペナルティ
    -   重み$c$の有向辺$u \to v$を張る

これを利用して:

-   頂点$v$が赤なら$c \ge 0$のペナルティ
    -   重み$c$の有向辺$v \to T$を張る
-   頂点$v$が青なら$c \ge 0$のペナルティ
    -   重み$c$の有向辺$S \to v$を張る
-   頂点$u$と頂点$v$の色が異なるなら$c \ge 0$のペナルティ
    -   重み$c$の無向辺$u - v$を張る
    -   つまり$2$本の有向辺$u \to v, \; v \to u$を張る

さらにこれらの$c = \infty$とすれば次も作れる:

-   頂点$u$が赤なら頂点$v$は必ず赤
-   頂点$v$は必ず青
    -   重み$\infty$の有向辺$v \to T$を張る
-   頂点$v$は必ず赤
-   頂点$u$と頂点$v$の色は必ず同じなる
    -   $u = v$としてひとつに潰してやるのでもよい

最初の制約「頂点$u$が赤かつ頂点$v$が青で塗られていれば$c \ge 0$のペナルティ」の形から、赤色に関しての制約が書ければ青色についても書けることが分かる。
以下は一方のみだけ示す。

ここまで全て$c \ge 0$である。ペナルティが負(つまり報酬)のときは先に報酬を貰ってしまうようにする:

-   頂点$u$が赤なら$- c$のペナルティ($c \ge 0$の報酬)
    -   制約「無条件で$- c$のペナルティ($c$の報酬)」「頂点$u$が青なら$c$のペナルティ」を足す

色が同じであることについては、報酬の形でのみ書ける。次のようにする:

-   頂点$u$と頂点$v$のどちらか一方以上が青なら$c \ge 0$のペナルティ
    -   新しい頂点$a$を用意し、制約「頂点$a$が赤なら頂点$u$も必ず赤」「頂点$a$が赤なら頂点$v$も必ず赤」「頂点$a$が青なら$c$のペナルティ」を足す
-   頂点$u$と頂点$v$が共に赤なら$- c$のペナルティ($c \ge 0$の報酬)
    -   制約「無条件で$- c$のペナルティ($c$の報酬)」「頂点$u$と頂点$v$のどちらか一方以上が青なら$c$のペナルティ」を足す

次の形の制約はおそらく書けないだろう:

-   (頂点$u$と頂点$v$が共に赤なら$c \ge 0$のペナルティ)
-   (頂点$u$が赤かつ頂点$v$が青で塗られていれば$- c$のペナルティ($c$の報酬))

また、次の形の制約も$\infty - \infty$のような形が現れるので面倒である。ただし$c$を十分大きな定数にすれば表現できる:

-   頂点$u$と頂点$v$が共に赤になることはない

制約に登場する頂点の数は$2$つとは限らない。次のような、単一の色にしか言及しない形であれば増やすことができる:

-   頂点$v\_0, \dots, v\_{k-1}$のいずれかひとつ以上が青なら$c \ge 0$のペナルティ
    -   新しい頂点$a$を用意し、制約「頂点$a$が赤なら頂点$v\_i$も必ず赤 ($0 \le i \lt k$)」「頂点$a$が青なら$c$のペナルティ」を足す
-   頂点$v\_0, \dots, v\_{k-1}$が全て赤なら$- c$のペナルティ($c \ge 0$の報酬)
    -   制約「無条件で$- c$のペナルティ($c$の報酬)」「頂点$v\_0, \dots, v\_{k-1}$のいずれかひとつ以上が青なら$c \ge 0$のペナルティ」を足す

## 以上の整理を踏まえてProject Selection Problemを解く

要素に対応するものと$S, T$で合計$N + 2$個の頂点を用意する。
要素が$A$に属するとき対応する頂点を赤、$B$に属するとき青で塗るとする。
制約は次のようにして帰着させられる:

-   「$A$に属するとき利得$p\_i \ge 0$を得る」は無条件の利得$p\_i$を準備し重み$p\_i$の有向辺$S \to x\_i$を張る
-   「$A$に属するとき利得$p\_i \le 0$を得る」は重み$\|p\_i\|$の有向辺$x\_i \to T$を張る
-   「$x\_j$が$A$に属しかつ$y\_j$が$B$に属していた時に$z\_j(\ge 0)$だけ損失」は重み$z\_j$の有向辺$x\_j \to y\_j$を張る

簡単ですね。
