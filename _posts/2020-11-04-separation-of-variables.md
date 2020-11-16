---
category: blog
layout: post
date: 2020-11-04T00:00:00+09:00
tags: [ "competitive" ]
---

# 競技プログラミングにおける変数分離


## 説明

変数分離とは微分方程式を解くための手法であるが、競技プログラミングにおいても類似の手法を用いることが多く見られる。競技プログラミングにおいてこの手法が陽に議論されることは少ないが、俗に「変数分離」という名で呼ばれている[^name][^prior][^importance]。
細かい差による派生形がいくつかあるが、最も基本となる形は「与えられた $2$ 変数述語 $\varphi(x, y)$ を、ある $1$ 変数関数 $f, g$ を用いて $\varphi(x, y) \leftrightarrow f(x) = g(y)$ と書き換える」である。

より具体的には、たとえば以下のような形で現われる。

-   区間 $\lbrack l, r) \subseteq \lbrack 0, n)$ に対する条件 $\varphi(l, r)$ が与えられ、これを満たすような区間の個数を求めたいとする[^nonempty]。たとえば「区間中の要素の平均が $k$ 以上」などである。このとき条件を $\varphi(l, r) \leftrightarrow f(l) = g(r)$ と書き換えられたとする。すると、区間中の位置 $i \in \lbrack 0, n)$ を「値 $f(l)$ を持つような位置 $l$ の個数」を管理しながら左から舐めることで、関数 $f, g$ の $O(n)$ 回の計算で答えが求まる。
-   長さ $n$ の順列 $p$ を「$i \lt j$ ならば $\varphi(p_i, p_j)$ を満たす」を満たすように構成したいとする。たとえば「$i$ を使った後に $j$ を使うには $a_i b_j \lt a_j b_i$ でなければならない」など。このとき条件をある $1$ 変数関数 $f$ を用いて $\varphi(i, j) \leftrightarrow f(i) \lt f(j)$ という形に書き換えられれば、$f(i)$ の値でソートしてこの順に使う貪欲法で答えが求まる。


## 例題1

### 問題

長さ $n$ の数列 $a = (a_0, a_1, \dots, a _ {n-1})$ と整数 $k$ が与えられ、条件 $\varphi(l, r) \leftrightarrow a_l + a _ {l+1} + \dots + a _ {r-1} = k$ を満たす区間 $\lbrack l, r) \subseteq \lbrack 0, n)$ の個数を求めよ。

たとえば、$a = (1, 2, 3, 1, 4)$ かつ $k = 4$ のとき、$a_2 + a_3 = 3 + 1 = 4 = k$ なので区間 $\lbrack 2, 4)$ は条件を満たし、$a_4 = k$ なので区間 $\lbrack 4, 5)$ も条件を満たし、それ以外に条件を満たす区間はないので、答えは $2$ である。

### 解法

累積和 $b_i = a_0 + a_1 + \dots + a _ {i-1}$ を使えば、条件は $\varphi(l, r) \leftrightarrow b_l + k = b_r$ と書き直せる。
$f(l) = b_l + k$ かつ $g(r) = b_r$ という変数分離の形にでき、累積和を求めておけばそれぞれの関数 $f, g$ は $O(1)$ である。
よってこの問題は $O(n)$ で解ける。

C++ による参考実装は以下のようになる。

``` c++
int64_t solve(int n, const vector<int64_t> &a, int64_t k) {
    vector<int64_t> b(n + 1);
    partial_sum(a.begin(), a.end(), b.begin() + 1);
    unordered_map<int64_t, int> cnt;
    int64_t ans = 0;
    for (int i = 0; i < n; ++ i) {
        int64_t f_l = b[i] + k;
        int64_t g_r = b[i];
        cnt[f_l] += 1;
        ans += cnt[g_r];
    }
    return ans;
}
```

## 例題2

### 問題

長さ $H$ の整数のみからなる縦ベクトル $a = \begin{pmatrix} a_0 \\\\ a_1 \\\\ \vdots \\\\ a _ {H-1} \end{pmatrix}$ と、長さ $W$ の整数のみからなる横ベクトル $b = \begin{pmatrix} b_0 & b_1 & \dots & b _ {W-1} \end{pmatrix}$ と、整数 $k$ が与えられる。
ベクトル $a, b$ の積として得られる大きさ $H \times W$ の行列を $C = ab$ とする。
$C$ の成分に値が $k$ なものがいくつ含まれるかを求めてよ。

たとえば $a = \begin{pmatrix} 2 \\\\ 3 \end{pmatrix}$ かつ $b = \begin{pmatrix} 1 & 2 & 3 & 4 \end{pmatrix}$ かつ $k = 6$ とすると、$C = \begin{pmatrix} 2 & 4 & 6 & 8 \\\\ 3 & 6 & 9 & 12 \end{pmatrix}$ なので $C$ の $(0, 2)$ 成分と $(1, 1)$ 成分のふたつの値が $k$ に等しく、答えは $2$ となる。

### 解法

$a_y b_x = k$ となるような組 $(y, x)$ の個数を求めればよい。
これは $a_y = k / b_x$ と書けば変数分離形であり、$O(H + W)$ で答えが求まる。
ただし $k$ が $b_x$ の倍数でないならば、そのような $x$ と組にして条件を満たす $y$ は存在しないことに注意する。

C++ による参考実装は以下のようになる。

``` c++
int64_t solve(int h, const vector<int64_t> &a, int w, const vecotr<int64_t> &b, int64_t k) {
    unordered_map<int64_t, int> cnt;
    for (int64_t b_i : b) {
        if (k % b_i == 0) {
            cnt[k / b_i] += 1;
        }
    }
    int64_t ans = 0;
    for (int64_t a_i : a) {
        ans += cnt[a_i];
    }
    return ans;
}
```

## 例題3

<iframe width="560" height="315" src="https://www.youtube.com/embed/RHapB5LZuNI" frameborder="0" allow="accelerometer; autoplay; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>

## 問題集

-   [AtCoder Beginner Contest 166: E - This Message Will Self-Destruct in 5s](https://atcoder.jp/contests/abc166/tasks/abc166_e)
    -   対を数える
-   [AtCoder Beginner Contest 168: E - ∙ (Bullet)](https://atcoder.jp/contests/abc168/tasks/abc168_e)
    -   比を取って分類する形
-   [Codeforces Round #625 (Div. 1, based on Technocup 2020 Final Round): A. Journey Planning](https://codeforces.com/contest/1320/problem/A)
    -   分類に使う
-   [yukicoder No.1142 XOR と XOR](https://yukicoder.me/problems/no/1142)
    -   手順は多いが基本を繰り返すだけではある

## リンク

-   [変数分離 - Wikipedia](https://ja.wikipedia.org/wiki/%E5%A4%89%E6%95%B0%E5%88%86%E9%9B%A2)
-   [変数分離形の微分方程式の解法と例題 &#x7c; 高校数学の美しい物語](https://mathtrain.jp/hensubunrigata)
    -   通常の意味の変数分離について
-   [数列上の数の組み合わせであって不等式を満たすものの数を数える - Learning Algorithms](https://kokiymgch.hatenablog.com/entry/2020/11/03/143606)
    -   競技プログラミングにおける同様の話題についてのブログ記事

## 脚注

[^name]: この名前は合意の取れているものと思ってよいだろう。Twitter 上を検索すると複数人がこの概念をこの名前で呼んでいることが確認できる。
[^prior]: 少なくとも日本の競プロ界隈においてこの概念についてまとめたブログ記事などは見つからなかった。十分に自明だからだろう。
[^importance]: このような自明な概念が注目されることは少ないが、ひとまず言語化して整理しておくことには価値があるはずである。特に、それを用いるための (あるひとつの形式化における) 必要十分条件を明確にして再利用可能な形にしておくと、次回以降に使う際に考えるべきことが減らせてうれしい。
[^nonempty]: 簡単な修正により「非空な区間に限る」「区間の長さが $m$ 以下」「区間の長さが偶数の場合のみ」などの追加の条件にも対応可能である。
