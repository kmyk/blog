---
category: blog
layout: post
date: 2020-07-27T09:00:00+09:00
tags: [ "competitive", "cartesian-tree" ]
---

# 列を最小値で分割して再帰するパターンと Cartesian tree

## TL;DR

列を最小値で分割して再帰するパターンは典型だが、これは Cartesian tree という形で整理できる。


## 列を最小値で分割して再帰するパターン

### 説明

列を最小値で分割して再帰するパターンとは、数列 $a = (a_0, a_1, \dots, a _ {n-1})$ に対して定まる値 $f(a_0, a_1, \dots, a _ {n-1})$ の計算を、$i \in \mathrm{argmin} _ j a_j$ であるような位置 $i$ で列 $a$ を 分割するような分割統治で行うパターンのことである。
以降で紹介する例題を見ながら帰納的に把握してほしい。

このパターンにはいくつかの変種がある。代表的なものに、最小値でなく最大値を使うものと、$a$ が distinct でなく $\mathrm{argmin} _ j a_j$ が複数のとき、同時に $\vert \mathrm{argmin} _ j a_j \vert + 1$ 個の列に分割するものとがある。

### 例題 1: Codeforces, Manthan, Codefest 18 (rated, Div. 1 + Div. 2): F. Maximum Reduction

問題: <https://codeforces.com/contest/1037/problem/F>

#### 問題概要 

長さ $n$ の列を長さ $n - k + 1$ の列に変換する関数 $z_k$ を、数列 $a = (a_0, a_1, \dots, a _ {n-1})$ と正整数 $k \ge 2$ に対し $z_k(a) = (\max \lbrace a_0, a_1, \dots, a _ {k-1} \rbrace, \max \lbrace a_1, a_2, \dots, a_k \rbrace, \dots, \max \lbrace a _ {n-k-1}, a _ {n-k}, \dots, a _ {n-1} \rbrace)$ で定義する。
ただし $n \lt k$ のときは $z_k(a) = \epsilon$ (ただし $\epsilon$ は空列) である。

たとえば $a = (9,2,1,4,5,7)$ かつ $k = 3$ のとき、$z_k(a) = (9, 4, 5, 7)$ かつ $z_k(z_k(a)) = (9, 7)$ かつ $z_k(z_k(z_k(a))) = \epsilon$ である。

数列 $a = (a_0, a_1, \dots, a _ {n-1})$ と正整数 $k \ge 2$ が与えられる。
列 $a$ が空列 $\epsilon$ になるまで関数 $z_k$ を繰り返し適用し、その過程で得られる数列 $a, z_k(a), z_k(z_k(a)), \dots$ すべてを連結したものを数列 $b$ とする。
このとき数列 $b$ に含まれる要素の総和を求めよ。

たとえば $a = (9,2,1,4,5,7)$ かつ $k = 3$ のとき、答えは $(9 + 2 + 1 + 4 + 5 + 7) + (9 + 4 + 5 + 7) + (9 + 7) = 69$ である。

#### 解法 

列 $a = (a_0, a_1, \dots, a _ {n-1})$ 中の最大値に注目して分割する。
列 $a$ に対する答えを $f(a)$ と書くとすると、$n \ge k$ のとき、最大値 $a_i = \max_j a_j$ (複数あるときはどれでもよいのでひとつ固定する) を使って $f(a_0, a_1, \dots, a _ {n-1}) = f(a_0, a_1, \dots, a _ {i-1}) + (l_k(n) - l_k(i) - l_k(n - i - 1)) \cdot a_i + f(a _ {i+1}, a _ {i+2}, \dots, a _ {n-1})$ が成り立つ。ただし $l_k(n)$ は長さ $n$ の列 $a$ から初めたときの結果の列 $b$ の長さとする。

最大値の位置を segment tree や sparse table などで求めれば、計算量は全体で $O(N \log N)$ となる。最大値の位置を Cartesian tree (定義は後で紹介する) を使って求めれば、計算量は $O(N)$ になる。

具体例も見ておこう。
たとえば列 $a = (1,2,3,2,9,3,4,5,6,7)$ かつ $k = 2$ のときの結果の列 $b$ を図にすると次のようになる。

```
1 2 3 2 9 3 4 5 6 7
  3 3 9 9 9 5 6 7
    9 9 9 9 9 7
      9 9 9 9
        9 9
```

このような三角形から最大値 $a_4 = 9$ の影響範囲の長方形を取り除けば次のようになる。この左右の三角形も同様に最大値 $3, 7$ で分割できる。

```
1 2 3 2   3 4 5 6 7
  3 3       5 6 7
              7
```


### 例題 2: Google Code Jam 2019, Round 3 2019:  Pancake Pyramid (5pts, 17pts)

問題: <https://codingcompetitions.withgoogle.com/codejam/round/0000000000051707/00000000001591be>

#### 問題概要

整数列 $a = (a_0, a_1, \dots, a _ {n-1})$ が pyramid property を満たすとは、ある $i \lt n$ が存在し $a_0 \le a_1 \le \dots \le a_i$ および $a_i \ge a _ {i+1} \ge \dots \ge a _ {n-1}$ が成り立つことをいう。
整数列 $a$ を pyramidification するとは、$a$ のいくつかの要素に非負整数を足して pyramid property が成り立つようにすることをいう。
整数列 $a$ の pyramidification cost とは、$a$ を pyramidification するために足す必要のある非負整数の総和の最小値をいう。

たとえば、$a = (5, 4, 2, 7, 1)$ を最適に pyramidification する方法は $a_1, a_2$ にそれぞれ $1, 3$ を足して $a' = (5, 5, 5, 7, 1)$ とすることであり、このため $a$ の pyramidification cost は $4$ である。

整数列 $a = (a_0, a_1, \dots, a _ {n-1})$ が与えられる。長さ $3$ 以上のすべての区間 $\lbrack l, r) \subseteq \lbrack 0, n)$ に対し、それぞれ列 $(a_l, a _ {l+1}, \dots, a _ {r-1})$ の pyramidification cost を求め、その総和を答えよ。

たとえば $a = (5, 4, 2, 7, 1)$ であれば、その長さ $3$ 以上の区間に対応する部分列は $(5, 4, 2, 7, 1), (5, 4, 2, 7), (4, 2, 7, 1), (5, 4, 2), (4, 2, 7), (2, 7, 1)$ の $6$ 個であり、それぞれの pyramidification cost は $4, 4, 2, 0, 2, 0$ であり、その総和は $12$ である。

#### 解法 

列 $a = (a_0, a_1, \dots, a _ {n-1})$ の全体での最大値 $a_i = \max_j a_j$ (複数ある場合はどれでもよいのでひとつ固定する) を含むような区間についてのみの総和を求め、その後その最大値を削除してできる左右の列について再帰することにする。

最大値 $a_i$ を含むような区間を pyramidification するコストの総和を求める問題に帰着された。
求めるべきものを整理しよう。
$a_i$ の左側を広義単調増加にするためのコストの総和を求めるのと $a_i$ の右側を広義単調減少にするためのコストの総和を求めるのは同様にできるので、左側を広義単調増加にするコストだけ考えれば十分である。列を反転させてもう一度やることにするなどしてもよい。
ただし「左側を広義単調増加にするコストの総和」とは、正確には、$i$ 個の列 $(a_0, a_1, \dots, a _ {i-1}), (a_1, a_2, \dots, a _ {i-1}), \dots, (a _ {i-2}, a _ {i-1}), (a _ {i-1})$ のそれぞれを広義単調増加にするコストの総和である。
この $i-1$ 個のコストの総和を $f(a_0, a_1, \dots, a _ {i-1})$ と書くことにする。
なお、$a_i$ の右側をどのようにするかの自由度があるので、実際の答えへの寄与は $f(a_0, a_1, \dots, a _ {i-1}) \cdot (n - i)$ となる。

$f(a_l, a _ {l+1}, \dots, a _ {r-1})$ を求める問題に帰着された。
これは再帰で解く。
まず $\lbrack l, r)$ 中の最大値 $a_m = \max _ {i \in \lbrack l, r)} a_i$ の位置 $m$ を求める。
列 $(a_i, a _ {i+1}, \dots, a _ {r-1})$ のみに対するコストを「列を $i$ まで伸ばした場合のコスト」と呼ぶことにし、列を $m$ よりも遠くへ伸ばす場合のコストと、列を $m$ の手前までのみ伸ばす場合のコストとをそれぞれ求める。
このとき $\forall i \in \lbrack m + 1, r).~ a_m \ge a_i$ なので、$\lbrack m + 1, r)$ の範囲の値をすべて $a_m$ まで増やすためのコストは $g(m + 1, r) = (r - m - 1) \cdot a_m - \sum _ {i \in \lbrack m+1, r)} a_i$ である。これを使って、列を $m$ よりも遠くへ伸ばす場合のコストの総和は $f(a_l, a _ {l+1}, \dots, a _ {m-1}) + (m - l + 1) \cdot g(m + 1, r)$ である。
列を $m$ の手前までのみ伸ばす場合のコストは、再帰で得られる $f(a _ {m+1}, a _ {m+2}, \dots, a _ {r-1})$ そのままである。
これで $f(a_l, a _ {l+1}, \dots, a _ {r-1})$ が求まった。
計算量は全体で $O(N)$ である。


### 例題 3: yukicoder No.1031 いたずら好きなお姉ちゃん

問題: <https://yukicoder.me/problems/no/1031>

#### 問題概要 

distinct な数列 $a$ 上の長さ $2$ 以上の区間 $\lbrack l, r) \subseteq \lbrack 0, n)$ を選び、その区間中の最小値と最大値を交換して新しい数列 $a'$ を作る、という操作を考える。

たとえば $a = (1, 4, 5, 3, 2, 0)$ のとき $\lbrack l, r) = \lbrack 0, 3)$ ならば $a' = (5, 4, 1, 3, 2, 0)$ である。

distinct な数列 $a = (a_0, a_1, \dots, a _ {n-1})$ が与えられる。$a$ に対しこのような操作をちょうど $1$ 回行なって得られる数列の種類数を求めよ。

たとえば $a = (0, 2, 1)$ のとき、$\lbrack 0, 2)$ や $\lbrack 0, 3)$ で $a' = (2, 0, 1)$ が作れ、$\lbrack 1, 3)$ で $a' = (0, 1, 2)$ が作れる。これ以外には $a$ から作れる列はないので、答えは $2$ である。

#### 解法

列 $a = (a_0, a_1, \dots, a _ {n-1})$ の全体での最小値 $a_i = \max_j a_j$ を含むような区間から作られる列のみ数え、その後その最小値を削除してできる左右の列について再帰することにする。

最小値 $a_i$ を含むような区間から作られる列を数える問題に帰着された。
これは最小値 $a_i$ と交換されるもう一方の数 $a_j$ について数えることと同じである。
ところで、列を反転させて後でもう一度繰り返すことにすれば $i \lt j$ を仮定して構わない[^typical]。
すると $\forall k \in \lbrack i, j).~ a_k \lt a_j$ を満たすような $a_j$ の個数を数えればよいと言える。
このとき、数えたい値は区間 $\lbrack i + 1, n)$ に対する left-to-right maxima の長さに等しい。
ただし、一般に、数列 $a$ の要素 $a_i$ であって $\forall j \lt i.~ a_j \lt a_i$ を満たすようなものを (その位置の情報を含めて) outstanding element と呼び、列 $a$ からその outstanding elements をすべて集めてきてできる部分列を $a$ の left-to-right maxima と呼ぶ[^greedily]。

区間がクエリとして与えられるのでその区間の left-to-right maxima の長さを求める問題に帰着された。
これを適当な方法で解けばよい。
単なる平方分割や rollback を使う Mo's algorithm を使えば全体で $O(N \sqrt{N} \log N)$ や $O(N \sqrt{N})$ 程度で解ける[^sqrt]。
doubling を使えば left-to-right maxima の長さの問題は構築 $O(N \log N)$ かつクエリ $O(\log N)$ で解ける。
left-to-right maxima の性質に沿った根付き木の森を作り、その頂点の深さの列を range min query の解けるデータ構造に乗せれば、構築 $O(N \log N)$ かつクエリ $O(1)$ で解ける。
全体では $O(N \log N)$ 程度となる[^fastrmq]。

left-to-right maxima の長さを range min query を使って求める方針について、より詳しく説明しておく。
まず、$a_i$ とそれより大きい最左の要素 $a_j$ (ただし $i \lt j$) の間に $i \to j$ と辺を張って根付きの木 (大きい要素が根) の森を作る。
その森における要素の深さを求め、その深さの列を $d$ とする。
たとえば列 $a = (3, 9, 1, 8, 10, 3, 4, 5)$ ならば深さの列は $d = (2, 1, 2, 1, 0, 2, 1, 0)$ である[^mistake]。
このとき区間 $\lbrack l, r)$ の left-to-right maxima の長さは、$l$ から辿り着ける $\lbrack l, r)$ 中の 要素の中で最も浅い位置のものを $x$ として $d_x - d_l$ となることが言える。
ここで、列 $d$ の作り方により、この $d_x$ の値は単に $\min _ {y \in \lbrack l, r)} d_y$ に一致する。
よって、この列 $d$ を RMQ に乗せれば left-to-right maxima の長さが求まる[^ltrmaxima]。


## Cartesian tree

### 定義

distinct な数列 $a = (a_0, a_1, \dots, a _ {n-1})$ に対する Cartesian tree とは、以下の条件を満たす二分木のこと。これは常に一意に存在する。

-   頂点の集合が数列 $a$ の項と一対一に対応する。つまり、それぞれの頂点 $x$ は対応する項の値 $a_i$ を重み $w_x = a_i$ として持つ。
-   対応する項の添字について二分探索木である。つまり、木の in-order での訪問順に頂点の重み $x_w = a_i$ を並べると数列 $a$ になる。
-   対応する項の値について heap 条件を満たす。つまり、親の重みは子の重みより小さい。

### 例

以下の図[^cc0]は列 $a = (9, 3, 7, 1, 8, 12, 10, 20, 15, 18, 5)$ と、この列から構成される Cartesian tree を表している。

![Cartesian_tree.svg](https://upload.wikimedia.org/wikipedia/commons/d/d5/Cartesian_tree.svg)

### 性質など

-   構築は $O(n)$ でできる。通常の heap と同様に、列を順番に舐めて木に要素を追加していけばよい。
    -   参考実装: <https://github.com/kmyk/competitive-programming-library/blob/f51247221743d4d0edd3c026eb8422461496caaf/graph/cartesian_tree.hpp>
-   「数列 $a$ から構築された」という情報を忘却して木として見るとただの heap 構造になる。
-   類似の異なる木として Treap がある。「Treap が構成している木構造は Cartesian tree だと思うことができる」は正しいが、「Treap と Cartesian tree は同じものである」とまでは言えない[^treap]。
-   日本語で書くとすると「デカルト木」とすることが多そう[^japanese]。
-   distinct 制約を抜いて多分木にするという拡張が考えられる[^extname]。
-   verify 用の問題は [Cartesian Tree - Library Checker](https://judge.yosupo.jp/problem/cartesian_tree) にあります[^contribution]。


## 列を最小値で分割して再帰するパターンと Cartesian tree の関係

### 関係

列を最小値で分割して再帰するパターンの再帰構造は Cartesian tree である[^dokuzi][^generalize]。
具体的には、各関数呼び出しで最小値として削除される要素を頂点とし、再帰呼び出し関係を辺として木構造を得ると、それが Cartesian tree と一致する。

この関係のため、列を最小値で分割して再帰するパターンは、次の $2$ ステップに分解して実装できる。

1.  Cartesian tree を構築する
1.  構築した Cartesian tree の上を再帰する

このような実装の例としては、すでに例題 3 として紹介した問題 [yukicoder No.1031 いたずら好きなお姉ちゃん](https://yukicoder.me/problems/no/1031) に対する提出 <https://yukicoder.me/submissions/512068> を参照してほしい。

列を最小値で分割して再帰するパターンの distinct 制約がない場合の変種についても、Cartesian tree を多分木に拡張する必要はあるが、同様の関係が成り立つ。

### うれしさ

この関係のうれしさは主に以下の $3$ 点である[^third]。

1.  きれいかつ再利用しやすい形でライブラリ化できるのでうれしい。「callback 関数をたくさん渡す」「むりやり代数の言葉で表現する」でなく「再帰構造や計算グラフを木として陽に取り出し、それに沿って答えを求める」は扱いやすい。
2.  分割のための最小値の位置を求める操作に Cartesian tree を使うと、segment tree や sparse table を使うより高速なのでうれしい。計算量が $O(N \log N)$ から $O(N)$ に落ちる[^rmq]。
3.  競プロ的に曖昧にしか認識できてなかったパターンが、学術界隈の用語を使って定義できるようになるのでうれしい。たとえば「列を最小値で分割して再帰するパターンとは、与えられた列から構築した Cartesian tree に対する畳み込み[^fold]として答えを求めるパターンである」などという説明が可能になる。


## リンク

-   [Cartesian tree - Wikipedia](https://en.wikipedia.org/wiki/Cartesian_tree)
-   [Cartesian Tree - Library Checker](https://judge.yosupo.jp/problem/cartesian_tree)


---

[^dokuzi]: 独自研究です。わりとそのままだから暗黙にはよく知られていそうだが、陽に書かれた記事などは見つけられなかった
[^third]: 個人的には、「なんでもモノイドを使って言い換えればよいというわけじゃないですよ」を主張するときに役立つきれいな例って感じがしてうれしいというのもある
[^treap]: たぶん。"Cartesian tree (Treap)" とか「Treap (Cartesian Tree) とは」とか書いてる記事が多くて不安になる
[^japanese]: "Cartesian" のカタカナ表記は「デカルト」の他にも「カルテシアン」や「カーテシアン」があり、こちらで書かれる可能性もある。面倒なので alphabet で書くのがおすすめ
[^extname]: このように拡張したものがどう呼ばれているかはよく分かりません
[^cc0]: 画像は public domain です。Wikipedia から借りてきました (<https://en.wikipedia.org/wiki/File:Cartesian_tree.svg>)
[^typical]: この「後で反転してもういちどやることにして、最大値の片側の部分についてだけ考える」というのも典型ぽい
[^generalize]: 一般に「複雑な再帰をする系のテクから木構造を取り出す」という枠組みが考えられる。こういう「何かの構造を分析すると別の構造が抽出される」みたいなやつ好き
[^greedily]: 一般的な用語です。"[greedily increasing subsequence](https://open.kattis.com/problems/greedilyincreasing)" とか呼ぶしかないのかなと思ってたところ、教えてもらった。感謝 (<https://twitter.com/maspy_stars/status/1283594702386638848>)
[^fold]: convolution ではなく fold のほうの畳み込み(<https://en.wikipedia.org/wiki/Catamorphism#Tree_fold>)。いわゆる木 DP
[^fastrmq]: ワードサイズ依存だが前処理 $O(N)$ かつクエリ $O(1)$ の RMQ は可能であり、これを使えば $O(N)$ になる。
[^rmq]: ワードサイズ依存だが前処理 $O(N)$ かつクエリ $O(1)$ の RMQ は可能であり、これを使えば Cartesian tree なしでも $O(N)$ になる: [https://qiita.com/okateim/items/e2f4a734db4e5f90e410](Range Minimum Query  - Qiita)
[^ltrmaxima]:  実装例: <https://github.com/kmyk/competitive-programming-library/blob/8e91b48cfab07c09c4f2594defe43915e7134f9e/utils/left_to_right_maxima.hpp>
[^sqrt]: 平方分割は writer の想定解だけど実装がかなり面倒なはず。Mo's algorithm を使うのは、計算量を $O(N \sqrt{N})$ に抑えるために償却計算量と Mo's algorithm の細部について議論する必要があり、よく見るとけっこう非自明です
[^mistake]: この深さの列って、なんとなく Cartesian tree に似ていると思いませんか？ 実際、Cartesian tree の実装を間違えるとこの列が得られてしまいます
[^contribution]: この記事を書くついでにプルリクを投げて問題を追加しました。
