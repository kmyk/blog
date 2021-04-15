---
layout: post
date: 2018-08-15T03:44:40+09:00
tags: [ "competitive", "writeup", "csacademy", "dp", "sort" ]
"target_url": [ "https://csacademy.com/contest/ceoi-2018-day-1/task/cloud-computing/" ]
redirect_from:
  - /writeup/algo/csacademy/ceoi-2018-day-1-cloud-computing/
  - /writeup/algo/cs-academy/ceoi-2018-day-1-cloud-computing/
---

# CS Academy CEOI 2018 Day 1: Cloud Computing

## solution

$f_i, F_j$の降順にsortしてDP (典型)。
周波数$f$な計算機/注文まで処理して周波数$f$以上の計算機が$c$個余っているような状態での利益の最大値を$v = \mathrm{dp}(f, c)$とおき、これを計算する。
$O((n + m) \cdot (\log (n + m) + \sum c_i))$。

## note

「計算機はすべて買わなければならない」「注文はすべて処理しなければならない」あるいは「$c_i = C_j = 1$ のとき」などの強めの制約を加えて考えてみると辿り着けるだろう。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define REP_R(i, n) for (int i = int(n) - 1; (i) >= 0; -- (i))
#define ALL(x) begin(x), end(x)
using ll = long long;
using namespace std;
template <class T> inline void chmax(T & a, T const & b) { a = max(a, b); }

struct resource_t {
    int c;
    ll f, v;
};

ll solve(int n, vector<resource_t> const & src, int m, vector<resource_t> const & dst) {
    // sort by f
    vector<ll> all_f;
    map<ll, vector<int> > src_f, dst_f;
    REP (i, n) {
        all_f.push_back(src[i].f);
        src_f[src[i].f].push_back(i);
    }
    REP (j, m) {
        all_f.push_back(dst[j].f);
        dst_f[dst[j].f].push_back(j);
    }
    sort(all_f.rbegin(), all_f.rend());
    all_f.erase(unique(ALL(all_f)), all_f.end());

    // dp
    vector<ll> dp(1, LLONG_MIN);
    dp[0] = 0;
    for (ll f : all_f) {
        int sum_c = dp.size();

        // for src
        if (src_f.count(f)) {
            for (int i : src_f[f]) {
                sum_c += src[i].c;
            }
            dp.resize(sum_c, LLONG_MIN);
            for (int i : src_f[f]) {
                int c_i = src[i].c;
                ll  v_i = src[i].v;
                REP_R (c, sum_c - c_i) if (dp[c] != LLONG_MIN) {
                    chmax(dp[c + c_i], dp[c] - v_i);
                }
            }
        }

        // for dst
        if (dst_f.count(f)) {
            for (int j : dst_f[f]) {
                int c_j = dst[j].c;
                ll  v_j = dst[j].v;
                REP (c, sum_c - c_j) if (dp[c + c_j] != LLONG_MIN) {
                    chmax(dp[c], dp[c + c_j] + v_j);
                }
            }
        }
    }
    return *max_element(ALL(dp));
}

int main() {
    // input
    int n; cin >> n;
    vector<resource_t> src(n);
    REP (i, n) cin >> src[i].c >> src[i].f >> src[i].v;
    int m; cin >> m;
    vector<resource_t> dst(m);
    REP (i, m) cin >> dst[i].c >> dst[i].f >> dst[i].v;

    // solve
    ll answer = solve(n, src, m, dst);

    // output
    cout << answer << endl;
    return 0;
}
```
