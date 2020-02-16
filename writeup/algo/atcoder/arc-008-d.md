---
layout: post
alias: "/blog/2015/11/10/arc-008-d/"
date: 2015-11-10T23:05:27+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "matrix", "segment-tree", "coordinates-compression" ]
---

# AtCoder Regular Contest 008 D - タコヤキオイシクナール

典型感あふれる問題。蟻本読んでれば難しくない。

<!-- more -->

## [D - タコヤキオイシクナール](https://beta.atcoder.jp/contests/arc008/tasks/arc008_4) {#d}

### 問題

たこ焼きを通過させると、その美味しさを$x \mapsto ax + b$にするボックスが$n$個($n \le 10^{12}$)ある。
ボックスの変数$a, b$は始めは全て$1, 1$であった。
$p_i$番目のボックスの変数を$a_i, b_i$に変化させる、という処理を$m$回($m \le 10^5$)行う。
この過程の全ての時点の中で、美味しさ$1$のたこ焼きをして全てのボックスを順に通過させた結果の美味しさの、最大値と最小値を求めよ。

### 解法

座標圧縮し、ボックスを行列として扱い、更新はsegment木で管理。$O(m \log m)$。
クエリが空の場合に注意。

### 実装

``` c++
#include <iostream>
#include <cstdio>
#include <cmath>
#include <vector>
#include <set>
#include <map>
#include <algorithm>
#include <cassert>
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define repeat(i,n) repeat_from(i,0,n)
typedef long long ll;
using namespace std;
struct mat_t {
    double a[2][2];
};
mat_t operator * (mat_t const & a, mat_t const & b) {
    mat_t c = {};
    repeat (y,2) {
        repeat (x,2) {
            repeat (z,2) {
                c.a[y][x] += a.a[y][z] * b.a[z][x];
            }
        }
    }
    return c;
}
mat_t unit() {
    return (mat_t){ { { 1, 0 }, { 0, 1 } } };
}
struct segtree_t {
    vector<mat_t> a;
    int n;
    explicit segtree_t(int a_n) {
        n = pow(2,ceil(log2(a_n)));
        a.resize(2*n-1, unit());
    }
    void update(int i, mat_t x) {
        i += n;
        a[i-1] = x;
        i /= 2;
        while (i) {
            a[i-1] = a[i*2+1-1] * a[i*2-1]; // reversed
            i /= 2;
        }
    }
    mat_t const & get() {
        return a[0];
    }
};
pair<double, double> solve(vector<int> const & p, vector<double> const & a, vector<double> const & b) {
    double mn = 1;
    double mx = 1;
    int m = p.size();
    if (m) {
        int n = 1 + *max_element(p.begin(), p.end());
        segtree_t t(n);
        repeat (i,m) {
            mat_t f = { { { a[i], b[i] }, { 0, 1 } } };
            t.update(p[i], f);
            mat_t g = t.get();
            double y = g.a[0][0] + g.a[0][1];
            mn = min(mn, y);
            mx = max(mx, y);
        }
    }
    return make_pair(mn, mx);
}
pair<double, double> solve(vector<ll> const & p, vector<double> const & a, vector<double> const & b) {
    // coordinates compression
    set<ll> ps(p.begin(), p.end());
    map<ll,int> pm;
    for (ll it : ps) {
        int i = pm.size(); // required to evaluate .size() before operator []
        pm[it] = i;
    }
    int m = p.size();
    vector<int> q(m);
    repeat (i,m) q[i] = pm[p[i]];
    return solve(q, a, b);
}
int main() {
    ll n; int m; cin >> n >> m;
    vector<ll> p(m);
    vector<double> a(m), b(m);
    repeat (i,m) cin >> p[i] >> a[i] >> b[i];
    double mn, mx;
    tie(mn, mx) = solve(p, a, b);
    printf("%.12lf\n", mn);
    printf("%.12lf\n", mx);
    return 0;
}
```
