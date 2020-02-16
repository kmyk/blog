---
layout: post
redirect_from:
  - /blog/2017/12/19/icpc-2017-asia-b/
date: "2017-12-19T03:49:14+09:00"
tags: [ "competitive", "writeup", "icpc", "icpc-asia", "dp", "bit-dp" ]
---

# AOJ 1379 / ACM-ICPC 2017 Asia Tsukuba Regional Contest: B. Parallel Lines

-   <http://judge.u-aizu.ac.jp/onlinejudge/description.jsp?id=1379>
-   <http://judge.u-aizu.ac.jp/onlinejudge/cdescription.jsp?cid=ICPCOOC2017&pid=B>

## problem

$2$次元平面上の点が$m$個与えられる。
$m$は偶数であり$3$点が一直線上に乗ることはない。
(これらの点をそれぞれ$1$度ずつ使って)これらを端点とする$\frac{m}{2}$本の線分を引き、平行な線分の対の数を最大化せよ。

## solution

bit-DP。使用した点の集合$s \subseteq \mathcal{P}(m)$に対し$\mathrm{dp}(s)$を平行な線分の対の数の最大値とする。事前に${}\_mC\_2$個の点対について角度を求めておき考えるべき角度を$a\_0, a\_1, \dots, a\_{k-1}$と列挙しておき、角度$a\_i$を持つような線分の数を$b\_i$として、$O(\sum\_{0 \le i \lt k}2^{b\_i})$での更新を$2^m$回する。$\sum\_{0 \le i \lt k}2^{b\_i} \approx 2^{\max\_i b\_i} = 2^{\frac{m}{2}}$としてよい(はず)なので$O(2^{\frac{3}{2}m})$。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
using namespace std;
template <class T> inline void chmax(T & a, T const & b) { a = max(a, b); }
template <typename T> T gcd(T a, T b) { while (a) { b %= a; swap(a, b); } return b; }

int main() {
    // input
    int m; scanf("%d", &m);
    assert (m % 2 == 0);
    vector<int> x(m), y(m);
    REP (i, m) scanf("%d%d", &x[i], &y[i]);
    // solve
    map<pair<int, int>, vector<int> > from_angle;
    REP (j, m) REP (i, j) {
        int dy = y[j] - y[i];
        int dx = x[j] - x[i];
        int d = gcd(abs(dy), abs(dx));
        dy /= d;
        dx /= d;
        if (dy < 0) { dy *= -1; dx *= -1; }
        if (dy == 0) dx = 1;
        if (dx == 0) dy = 1;
        from_angle[make_pair(dy, dx)].push_back((1 << i) | (1 << j));
    }
    vector<int> dp(1 << m, -1);
    dp[0] = 0;
    REP (s, 1 << m) if (dp[s] != -1) {
        for (auto pairs : from_angle) {
            vector<int> ts;
            ts.push_back(0);
            for (int dt : pairs.second) {
                if (s & dt) continue;
                for (int i = ts.size(); i --; ) {
                    int t = ts[i] | dt;
                    int k = __builtin_popcount(t) / 2;
                    chmax(dp[s | t], dp[s] + k * (k - 1) / 2);
                    ts.push_back(t);
                }
            }
        }
    }
    // output
    printf("%d\n", dp.back());
    return 0;
}
```
