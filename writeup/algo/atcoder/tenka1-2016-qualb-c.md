---
redirect_from:
  - /writeup/algo/atcoder/tenka1-2016-qualb-c/
layout: post
date: 2018-07-07T07:17:47+09:00
tags: [ "competitive", "writeup", "atcoder", "tenka1", "dp", "probability" ]
"target_url": [ "https://beta.atcoder.jp/contests/tenka1-2016-qualb/tasks/tenka1_2016_qualB_c" ]
---

# 天下一プログラマーコンテスト2016予選B: C - 天下一プログラマーコンテスト1999

## 解法

まず勝利数だけ気にすればよい。
アンドウくんが付けた対戦記録から求められる順位の順でとりあえずソートしたい。
となると、ハシモトくんが付けた勝利数の列を作ったとき、適切に単調減少していればよい。
これはDP。順位$i$位の人まで一致してかつ$i$位の人が$j$勝となるような確率を$\mathrm{dp}(i, j)$とする。$O(N^3)$。

自分自身との対戦結果にあたる場所が間違えて記録されることはないことに注意。

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define ALL(x) begin(x), end(x)
using namespace std;
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }

double choose(int n, int r) {
    double acc = 1;
    REP (i, r) {
        acc *= n - i;
        acc /= i + 1;
    }
    return acc;
}

vector<vector<double> > make_prob_matrix(int n, int p, int q) {
    double r = (double)p / q;
    auto prob = vectors(n + 1, n + 1, double());
    REP (a, n + 1) {
        int b = n - a - 1;  // NOTE: values on the diagonal are always correct
        REP (a1, a + 1) {
            REP (b1, b + 1) {
                prob[a][a1 + b1] += choose(a, a1) * pow(r, a1) * pow(1 - r, a - a1)
                                  * choose(b, b1) * pow(1 - r, b1) * pow(r, b - b1);
            }
        }
    }
    return prob;
}

int main() {
    // input
    int n, p, q; scanf("%d %d/%d", &n, &p, &q);
    auto a = vectors(n, n, int());
    REP (y, n) REP (x, n) scanf("%d", &a[y][x]);

    // solve
    vector<int> b(n);
    REP (y, n) REP (x, n) b[y] += a[y][x];
    auto prob = make_prob_matrix(n, p, q);

    vector<int> order(n);
    iota(ALL(order), 0);
    sort(ALL(order), [&](int y1, int y2) { return make_pair(- b[y1], y1) < make_pair(- b[y2], y2); });
    vector<double> cur(n + 1);
    cur[n] = 1;
    REP (i, n) {
        int y = order[i];
        bool is_strict = (i - 1 >= 0 and order[i - 1] > y);
        vector<double> nxt(n + 1);
        REP (c, n + 1) {
            REP (d, c + (not is_strict)) {
                nxt[d] += cur[c] * prob[b[y]][d];
            }
        }
        cur.swap(nxt);
    }

    // output
    double answer = accumulate(ALL(cur), 0.0);
    printf("%.12lf\n", answer);
    return 0;
}
```
