---
redirect_from:
layout: post
date: 2019-08-10T23:59:59+09:00
tags: ["competitive", "writeup"]
---

# Member SRM 458 Div 1: Medium. NewCoins

## 問題

製品の値段を表す数列 $\mathrm{price}$ が与えられる。
発行するコインの価値を数列 $x$ を条件 $$\begin{cases}
        x_1 = 1 \\
        \forall b. \forall a \lt b. x_a \mid x_b \\
\end{cases}$$ を満たすように決めて、それぞれの品物を (単体で) 買うのに必要なコインの枚数の総和を最小化せよ。

## 解法

動的計画法。列 $\mathrm{price}$ の長さを $N = \mathrm{lh}(\mathrm{price})$ かつ最大値を $A = \mathrm{max}(\mathrm{price})$ とすると、計算量は調和級数の和になって $O(N \cdot A \log A)$。

数列 $x$ についての条件は $$\begin{cases}
    x_1 = 1 \\
    \forall a. x_a \mid x _ {a + 1} \\
\end{cases}$$ と等しい。
これを使って、数列 $x$ を固定したときに値段 $p$ の製品を購入するのに必要なコインの枚数 $f(x, p)$ を考える。
すると $x$ を大きい順に貪欲に使うのが最適であることは明らか。
これを式で書くと $$f(x, p) = p / x _ {|x|} + (p \% x _ {|x|}) / x _ {|x| - 1} + (p \% x _ {|x| - 1}) / x _ {|x| - 2} + \dots$$ となる。
$F(x) = F(x, \mathrm{price}) = \sum_i f(x, \mathrm{price} _ i)$ を考えると $\sum$ の交換により
$$F(x) = \sum_i \mathrm{price} _ i / x _ {|x|} + \sum_i (\mathrm{price} _ i \% x _ {|x|}) / x _ {|x| - 1} + \sum_i (\mathrm{price} _ i \% x _ {|x| - 1}) / x _ {|x| - 2} + \dots$$ となる。
それぞれの $\sum_i (\mathrm{price} _ i \% x _ i) / x _ {i - 1}$ は隣接するコインにしか依存しない。
答えは $\min_x F(x) = \min_x \sum_i f(x, \mathrm{price} _ i)$ であるので、これは動的計画法で計算できる。

## 考察

1.  条件は $$\begin{cases}
        x_1 = 1 \\
        \forall b. \forall a \lt b. x_a \mid x_b \\
    \end{cases}$$ である
1.  条件は $$\begin{cases}
        x_1 = 1 \\
        \forall a. x_a \mid x _ {a + 1} \\
    \end{cases}$$ と等しい
1.  条件は $$\begin{cases}
        x_1 = 1 \\
        \forall a. \exists p : prime. x _ {a + 1} = p x_a \\
    \end{cases}$$ としてもよい
1.  つまりコイン列は素数列と一対一対応が付くとしてよい
1.  製品をソートして $i$ 番目まで見て、それまでに使った中で最も大きいコインを $x$ としたとき、必要なコインの枚数の最小値を $\mathrm{dp}(i, x)$ とする、がよさそう？
1.  しかし自明に嘘。 $1 \to 2 \to x = 6$ というコイン列と $1 \to 3 \to x = 6$ というコイン列を区別する必要がありかつ区別できない
1.  製品を上側から見るのはどうか？ コインの列は左右から伸びることになる。区別できないコイン列の問題は消えてないしだめそう
1.  最も大きいコインを固定して、いい感じに貪欲が正解だったりしないか？
1.  コイン $x_b$ を使うと決めたとき、製品の値段はそれまでのコインを使って $\mathrm{price} _ i \equiv 0 \pmod{x_b}$ にされねばならない
1.  コイン $1 = x_1$ が大嘘だったりしないか？
1.  じゃあコインを後ろから決めていくとよい？ それこそ嘘っぽい
1.  そもそも $\mathrm{price} _ i \equiv 0 \pmod{1}$ は恒真だった

(ここで実装して提出)

1.  WA でした
1.  よく考えたら経路依存の問題が消えてない。$\mathrm{price} = ( 12, 15 )$ のときは $\mathrm{coins} = (1, 3, 6, 12)$ が最適だけど、これは $12$ を処理した後もなお過去に $3$ を使ったという情報を持ってないとだめ
1.  解説を見た

## メモ

-   WA (55 分) + 諦め (70 分)
-   「$x$ の条件の整理」「剰余でいい感じにする」は気付けていたが「隣接するコインだけ見ればよい」がだめだった
-   「数列 $x$ を固定したときに値段 $p$ の製品を購入するのに必要なコインの枚数 $f(x, p)$ を考えてみましょう」をしなかったのが敗因ぽい

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < (int)(n); ++ (i))
#define ALL(x) begin(x), end(x)
using namespace std;
class NewCoins { public: int minCoins(vector<int> price); };

int NewCoins::minCoins(vector<int> price) {
    int n = price.size();
    sort(ALL(price));
    vector<vector<int> > dp(n + 1, vector<int>(price.back() + 1, INT_MAX));
    dp[0][1] = 0;
    REP (i, n) {
        REP (x, price.back() + 1) if (dp[i][x] != INT_MAX) {
            for (int k = 1; k * x <= price.back(); ++ k) {
                int acc = dp[i][x];
                if (k >= 2) {
                    REP3 (j, i + 1, n) {
                        int q_j = price[j] / x;
                        acc += q_j % k;
                    }
                }
                int q_i = price[i] / x;
                acc += q_i / k + q_i % k;
                dp[i + 1][k * x] = min(dp[i + 1][k * x], acc);
            }
        }
    }
    return *min_element(ALL(dp[n]));
}
```

## リンク

-   <https://community.topcoder.com/stat?c=problem_statement&pm=10569>
-   <https://apps.topcoder.com/wiki/display/tc/Member+SRM+458>
