---
redirect_from:
  - /writeup/algo/atcoder/soundhound2018-summer-qual-e/
layout: post
date: 2018-07-07T23:53:38+09:00
tags: [ "competitive", "writeup", "atcoder", "polynomial", "bipartite-graph" ]
"target_url": [ "https://beta.atcoder.jp/contests/soundhound2018-summer-qual/tasks/soundhound2018_summer_qual_e" ]
---

# SoundHound Inc. Programming Contest 2018 -Masters Tournament-: E - + Graph

## 解法

適当な$1$箇所を固定すれば残りがすべて定まるが、最初の$1$箇所をどうするかが問題。
そこで最初の値を$x$と置いて多項式を伝播させる (なんだか典型ぽい)。
$O(N + M)$。

頂点に多項式$f_i(x) = a_i x + b_i$を書いていく。
隣接する頂点について$g(x) := s - f(x)$として伝播させ、すでに固定された頂点同士は$f(x) + g(x) = s$であることを確認する。このとき$x$の値が一意に決定されるなら覚えておくようにする。
すべて成功したなら、すべての$f$について$f(x) \ge 1$となるような$x$の数を数えて出力。
$x$の値が未決定でない場合も確認が必要なことに注意。

二部グラフ判定をして丁寧に場合分けをしても解ける。
二分探索したさもあるが、最初の値は上限と下限の両方を持つのでたぶん無理。

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
using ll = long long;
using namespace std;
template <class T> inline void chmax(T & a, T const & b) { a = max(a, b); }
template <class T> inline void chmin(T & a, T const & b) { a = min(a, b); }

constexpr ll INF = (ll)1e18 + 9;
ll solve(int n, int m, vector<vector<pair<int, int> > > const & g) {
    vector<ll> a(n, INF);
    vector<ll> b(n, INF);
    ll x = INF;
    try {
        function<void (int)> dfs = [&](int i) {
            for (auto edge : g[i]) {
                int j, s; tie(j, s) = edge;
                if (a[j] == INF) {
                    // let: a_j x + b_j := s - (a_i x + b_i)
                    a[j] =   - a[i];
                    b[j] = s - b[i];
                    dfs(j);
                } else {
                    // solve: a_i x + b_i + a_j x + b_j = s
                    if (x == INF) {
                        ll num = s - b[i] - b[j];
                        ll den =     a[i] + a[j];
                        if (den == 0) {
                            if (num == 0) {
                                // nop
                            } else {
                                throw 0;
                            }
                        } else if (num % den != 0) {
                            throw 0;
                        } else {
                            x = num / den;
                        }
                    } else {
                        if ((a[i] * x + b[i]) + (a[j] * x + b[j]) != s) {
                            throw 0;
                        }
                    }
                }
            }
        };
        a[0] = 1;
        b[0] = 0;
        dfs(0);
    } catch (int) {
        return 0;
    }

    if (x != INF) {
        REP (i, n) {
            if (a[i] * x + b[i] <= 0) {
                return 0;
            }
        }
        return 1;

    } else {
        // x is arbitrary
        ll l = - INF;
        ll r = INF;
        REP (i, n) {
            // solve: a_i x + b_i > 0
            if (a[i] > 0) {
                chmax(l, (- b[i]) / a[i] + 1);
            } else if (a[i] < 0) {
                chmin(r, (- b[i]) / a[i] - 1);
            }
        }
        return max(0ll, r - l + 1);
    }
}

int main() {
    // input
    int n, m; cin >> n >> m;
    vector<vector<pair<int, int> > > g(n);
    REP (i, m) {
        int u, v, s; cin >> u >> v >> s;
        -- u; -- v;
        g[u].emplace_back(v, s);
        g[v].emplace_back(u, s);
    }

    // solve
    ll answer = solve(n, m, g);

    // output
    cout << answer << endl;
    return 0;
}
```
