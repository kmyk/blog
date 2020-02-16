---
layout: post
alias: "/blog/2018/04/09/abc-061-d/"
date: "2018-04-09T18:59:39+09:00"
tags: [ "competitive", "writeup", "atcoder", "abc", "bellman-ford", "longest-path-problem" ]
"target_url": [ "https://beta.atcoder.jp/contests/abc061/tasks/abc061_d" ]
---

# AtCoder Beginner Contest 061: D - Score Attack

## solution

最長経路問題だがpathは単純でなくてよい。
Bellman-Ford法とほぼ同じことをすれば$O(NM)$。

## note

-   「AtCoder上でBellman-Ford法を見たことないんだけど存在する？」って聞いたらこの問題が出てきた <https://twitter.com/Ymgch_K/status/983015780919885824>
-   一般に最長経路問題と呼ぶと単純pathの制限が付きNP完全。重みが全て$1$の場合Hamilton路問題と等しくなる。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
using ll = long long;
using namespace std;
template <class T> inline void chmax(T & a, T const & b) { a = max(a, b); }

constexpr ll inf = ll(1e18) + 9;

/**
 * @arg g is a digraph with possibly negative cost edges
 * @note - inf for unreachable node
 */
vector<ll> bellman_ford_longest_path(int root, vector<vector<pair<int, ll> > > const & g) {
    int n = g.size();
    vector<ll> dist(n, - inf);
    dist[root] = 0;
    REP (iteration, n - 1) {
        REP (i, n) for (auto edge : g[i]) {
            int j; ll cost; tie(j, cost) = edge;
            chmax(dist[j], dist[i] + cost);
        }
    }
    REP (iteration, n - 1) {
        REP (i, n) for (auto edge : g[i]) {
            int j; ll cost; tie(j, cost) = edge;
            if (dist[i] == inf or dist[j] < dist[i] + cost) {
                dist[j] = inf;
            }
        }
    }
    return dist;
}

ll solve(int n, int m, vector<vector<pair<int, ll> > > const & g) {
    return bellman_ford_longest_path(0, g)[n - 1];
}

int main() {
    int n, m; cin >> n >> m;
    vector<vector<pair<int, ll> > > g(n);
    REP (i, m) {
        int a, b, c; cin >> a >> b >> c;
        -- a; -- b;
        g[a].emplace_back(b, c);
    }
    ll answer = solve(n, m, g);
    if (answer == inf) {
        cout << "inf" << endl;
    } else {
        cout << answer << endl;
    }
    return 0;
}
```
