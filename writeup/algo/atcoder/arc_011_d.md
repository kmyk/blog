---
layout: post
date: 2018-09-04T04:48:34+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "geometry", "lie" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc011/tasks/arc011_4" ]
redirect_from:
  - /writeup/algo/atcoder/arc-011-d/
---

# AtCoder Regular Contest 011: D - きつねさんからの挑戦状

## 解法

嘘解法。
Voronoi図でどうこうとかやりたくない。
計算量は曖昧だがおよそ$O((N + M)R^2)$と言える。

まず $2R \times 2R$ の領域から $4000 \times 4000$ 個の点をサンプリングし最良のものを選ぶ。
関数は比較的ゆるやかなので間隔 $2R / 4000 \le 0.5$ は十分。
その付近に解があることが分かるので、ここから精度を上げればよい。
処理「見る領域をその付近の $\pm r$ に絞り $10 \times 10$ 程度をサンプリングし最良のものを選ぶ」を $r$ を$1/2$倍しながら$100$回ほど繰り返せば十分な精度で求まる。

## メモ

手元で `-O2` なら clnag++ 6.0.0 より g++ 7.3.0 の方が速かった。
`-O3` なら逆転。
CPUの改良により出題時より解きやすくなっているはず。

逐次改善的に求めるのは複数試したが失敗した。

## 実装

``` c++
#pragma GCC optimize "O3"
#pragma GCC target "avx"
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define ALL(x) begin(x), end(x)
using namespace std;
template <class T> inline void chmax(T & a, T const & b) { a = max(a, b); }

struct line_t { int a, b, c; };
struct point_t { int y, x; };

constexpr double eps = 1e-9;
double solve(int n, int m, int r, vector<line_t> const & lines, vector<point_t> const & points) {
    auto fl = [&](double y, double x) {
        double d1 = INFINITY;
        int i1 = -1;
        REP (i, n) {
            int a = lines[i].a;
            int b = lines[i].b;
            int c = lines[i].c;
            double num = pow(a * x + b * y + c, 2);
            double den = pow(a, 2) + pow(b, 2);
            if (num / den < d1) {
                d1 = num / den;
                i1 = i;
            }
        }
        return make_pair(i1, d1);
    };
    auto fp = [&](double y, double x) {
        double d2 = INFINITY;
        int j2 = -1;
        REP (j, m) {
            int y1 = points[j].y;
            int x1 = points[j].x;
            double d = pow(y - y1, 2) + pow(x - x1, 2);
            if (d < d2) {
                d2 = d;
                j2 = j;
            }
        }
        return make_pair(j2, d2);
    };
    auto f = [&](double y, double x) {
        double d1 = fl(y, x).second;
        double d2 = fp(y, x).second;
        return sqrt(d1) + d2;
    };

    tuple<double, double, double> p = make_tuple(- INFINITY, 0, 0);

    // first
    constexpr double K1 = 2000;
    for (double y = -r; y < r + eps; y += r / K1) {
        for (double x = -r; x < r + eps; x += r / K1) {
            chmax(p, make_tuple(f(y, x), y, x));
        }
    }

    // second
    double k = 1000;
    REP (iteration, 100) {
        double y0, x0; tie(ignore, y0, x0) = p;
        double ly = max<double>(-r, y0 - r / k);
        double ry = min<double>(+r, y0 + r / k);
        double lx = max<double>(-r, x0 - r / k);
        double rx = min<double>(+r, x0 + r / k);
        constexpr double K2 = 10;
        if ((ry - ly) / K2 < eps) break;
        if ((rx - lx) / K2 < eps) break;
        for (double y = ly; y < ry + eps; y += (ry - ly) / K2) {
            for (double x = lx; x < rx + eps; x += (rx - lx) / K2) {
                chmax(p, make_tuple(f(y, x), y, x));
            }
        }
        k *= 2;
    }

    return get<0>(p);
}

int main() {
    // input
    int n, m, r; cin >> n >> m >> r;
    vector<line_t> lines(n);
    REP (i, n) {
        cin >> lines[i].a >> lines[i].b >> lines[i].c;
    }
    vector<point_t> points(m);
    REP (j, m) {
        cin >> points[j].x >> points[j].y;
    }

    // solve
    double answer = solve(n, m, r, lines, points);

    // output
    cout << setprecision(16) << answer << endl;
    return 0;
}
```
