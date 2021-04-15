---
layout: post
date: 2018-08-31T18:26:50+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "dp", "expected-value", "linearity" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc034/tasks/arc034_4" ]
redirect_from:
  - /writeup/algo/atcoder/arc_034_d/
  - /writeup/algo/atcoder/arc-034-d/
---

# AtCoder Regular Contest 034: D - インフレゲーム

## 解法

期待値の線形性。
都度 $$b_j$$ を掛けるのでなく $$B_k = E \left [ \prod _ {j \in J} b_j \mid |J| = k \right ] $$ をそれぞれ求めておいてこの形でまとめて掛ければ線形性が得られる。
あとは普通にDP。
$$O((A+B)B)$$。

期待値の線形性より平均値 $$\dot{a} = \sum a_i / A$$ を用いて $$a_1 = a_2 = \dots = a_A = \dot{a}$$ と置き直してよいことは典型。
$$b$$ 側も同様にしたい。
しかし $$\dot{b} = \sqrt[B]{\prod b_j}$$ などでは上手くいかない。
これをなんとかしよう。
得られる結果の数式は例えば $$((0 + a _ {i_1}) \cdot b _ {j _ 1} + a _ {i_2} + a _ {i_3}) \cdot b _ {j _ 2} \cdot b _ {j _ 3} + a _ {i_4}$$ のような形をしている。
これを整理すると $$\dot{a} \cdot (b _ {j _ 1} b _ {j _ 2} b _ {j _ 3} + b _ {j _ 2} b _ {j _ 3} + b _ {j _ 2} b _ {j _ 3} + 1)$$ という形になる。
よってこの $$\prod _ {j \in J} b_j = b _ {j _ 1} b _ {j _ 2} b _ {j _ 3} \dots b _ {j _ k}$$ な項についてのみ考えればよい。
特に長さ$k$を固定したときの列中への出現回数の期待値とそれぞれの出現での大きさの期待値 $$B_k = E \left [ \prod _ {j \in J} b_j \mid |J| = k \right ] $$ を求め、線形性を用いてまとめればよい。
これはまったく普通のDP。

## メモ

体感700点

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define REP_R(i, n) for (int i = int(n) - 1; (i) >= 0; -- (i))
#define ALL(x) begin(x), end(x)
using ll = long long;
using namespace std;
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }

double solve(vector<int> a, vector<int> b, int c) {
    // by linearity
    double avg_a = accumulate(ALL(a), 0.0) / a.size();

    // take products to use linearity
    vector<double> avg_b(b.size() + 1); {
        vector<double> num(b.size() + 1);
        vector<ll> den(b.size() + 1);
        num[0] = 1;
        den[0] = 1;
        REP (j, b.size()) {
            REP_R (len, j + 1) {
                num[len + 1] += num[len] * b[j];
                den[len + 1] += den[len];
            }
        }
        REP (j, b.size() + 1) {
            avg_b[j] = num[j] / den[j];
        }
    }

    // dp
    auto memo = vectors(a.size() + 1, b.size() + 1, (double)NAN);
    function<double (int, int)> go = [&](int i, int j) {
        if (not std::isnan(memo[i][j])) return memo[i][j];
        double p = (double)(a.size() - i) / (a.size() - i + b.size() - j + c);
        double q = (double)(b.size() - j) / (a.size() - i + b.size() - j + c);
        double r = (double) c             / (a.size() - i + b.size() - j + c);
        double e = 0;
        if (p) e += p * (go(i + 1, j) + avg_a * avg_b[j]);
        if (q) e += q * go(i, j + 1);
        return memo[i][j] = e;
    };
    return go(0, 0);
}

int main() {
    int A, B, C; scanf("%d%d%d", &A, &B, &C);
    vector<int> a(A), b(B);
    REP (i, A) scanf("%d", &a[i]);
    REP (j, B) scanf("%d", &b[j]);
    double e = solve(a, b, C);
    printf("%.12lf\n", e);
    return 0;
}
```
