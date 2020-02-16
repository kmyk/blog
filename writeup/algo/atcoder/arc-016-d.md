---
layout: post
date: 2018-08-23T15:07:42+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "dp", "binary-search", "expected-value", "graph", "dag", "fixed-point" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc016/tasks/arc016_4" ]
---

# AtCoder Regular Contest 016: D - 軍艦ゲーム

## 解法

DP。答えを二分探索。
答えの最大値$E = 10^6$を使って $$O((N + M) H \log E)$$。

与えられるグラフはDAGであるので奥から順に期待値が計算できそう。
しかし答えの値$e$が分かっている必要がある。
このようなとき$$e = x \in \mathbb{R}[x]$$とおいて答えの多項式を計算するのは典型だが、非線形関数$\max$が関与するためこれはできない。
このようなとき代わりに考えるのは二分探索。
適当に$x \in \mathbb{R}$を決め打ちして計算し得られた結果を$f(x) \in \mathbb{R}$としよう。
真の答え$e$と比較して$x \le e$なら$x \le f(x) \le e$かつ$e \le x$なら$e \le f(x) \le x$が言える。
よって$x$と$f(x)$の比較を述語として答えの値が二分探索できる。
このとき$$\lim_i f^i(x) = e$$も言えるが収束が遅いので適さない。

## メモ

誤読した。
与えられるグラフはDAGのみというのを読み落とした。
有向閉路がある場合はかなり難しくなる気がするが解けるのだろうか。

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < (int)(n); ++ (i))
#define REP_R(i, n) for (int i = int(n) - 1; (i) >= 0; -- (i))
using namespace std;
template <class T> inline void chmax(T & a, T const & b) { a = max(a, b); }
template <class T> inline void chmin(T & a, T const & b) { a = min(a, b); }
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }

double solve(int n, int m, int h, vector<vector<int> > const & g, vector<int> const & d) {
    // check whether you can go to the goal
    vector<int> min_d(n, INT_MAX);
    min_d[n - 1] = 1;
    REP_R (i, n - 1) {
        int max_d = 0;
        for (int j : g[i]) {
            chmax(max_d, d[j]);
            if (min_d[j] != INT_MAX) {
                chmin(min_d[i], min_d[j] + d[j]);
            }
        }
        chmax(min_d[i], max_d + 1);
    }
    if (min_d[0] > h) {
        return INFINITY;  // impossible
    }

    auto solve1 = [&](double x) {
        auto dp = vectors(n, h + 1, (double)INFINITY);
        // the goal
        REP3 (c, 1, h + 1) {
            dp[n - 1][c] = 0;
        }

        REP_R (i, n - 1) {
            // return to the home
            REP3 (c, 1, h + 1) {
                dp[i][c] = (h - c) + x;
            }

            // go to a next ocean
            if (not g[i].empty()) {
                int max_d = 0;
                for (int j : g[i]) {
                    chmax(max_d, d[j]);
                }
                REP3 (c, max_d + 1, h + 1) {
                    double acc = 0;
                    for (int j : g[i]) {
                        acc += dp[j][c - d[j]];
                    }
                    double e = 1 + acc / g[i].size();
                    chmin(dp[i][c], e);
                }
            }
        }
        return dp[0][h];
    };

    // binary search
    double l = 0, r = 1e6;
    REP (iteration, 100) {
        double m = (l + r) / 2;
        (solve1(m) < m ? r : l) = m;
    }
    return r;
}

int main() {
    // input
    int n, m, h; cin >> n >> m >> h;
    vector<vector<int> > g(n);
    REP (i, m) {
        int f, t; cin >> f >> t;
        -- f; -- t;
        g[f].push_back(t);
    }
    vector<int> d(n);
    REP (i, n) {
        cin >> d[i];
    }

    // solve
    double e = solve(n, m, h, g, d);

    // output
    if (std::isinf(e)) {
        printf("%d\n", -1);
    } else {
        printf("%.12lf\n", e);
    }
    return 0;
}
```
