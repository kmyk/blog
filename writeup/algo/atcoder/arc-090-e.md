---
layout: post
redirect_from:
  - /blog/2018/04/09/arc-090-e/
date: "2018-04-09T23:19:41+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "graph" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc090/tasks/arc090_c" ]
---

# AtCoder Regular Contest 090: E - Avoiding Collision

## solution

$S \to T$最短路DAGを構築しそれだけ見ればよい。
ふたりが出会うような経路数を数えて全体から引く。
ちょうど中央にある頂点か辺の上で一度だけ出会うので、そのようにする。$O((N + M) \log N)$。

## note

-   高橋くんも青木くんも共に$S$から$T$へ移動するのだと誤読した。この設定の場合の解法は分からなかった。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define ALL(x) begin(x), end(x)
using ll = long long;
using namespace std;

vector<ll> dijkstra(vector<vector<pair<int, ll> > > const & g, int root) {
    vector<ll> dist(g.size(), LLONG_MAX);
    priority_queue<pair<ll, int> > que;
    dist[root] = 0;
    que.emplace(- dist[root], root);
    while (not que.empty()) {
        ll dist_i; int i; tie(dist_i, i) = que.top(); que.pop();
        if (dist[i] < - dist_i) continue;
        for (auto it : g[i]) {
            int j; ll cost; tie(j, cost) = it;
            if (- dist_i + cost < dist[j]) {
                dist[j] = - dist_i + cost;
                que.emplace(dist_i - cost, j);
            }
        }
    }
    return dist;
}

constexpr int mod = 1e9 + 7;
ll sq(ll x) { return x * x % mod; }

vector<int> count_path(vector<vector<pair<int, ll> > > const & g, int root, vector<ll> const & dist) {
    vector<int> cnt(g.size());
    vector<int> order(g.size());  // ascending by dist
    iota(ALL(order), 0);
    sort(ALL(order), [&](int i, int j) { return dist[i] < dist[j]; });
    for (int i : order) {
        if (i == root) {
            cnt[i] = 1;
        } else {
            ll acc = 0;
            for (auto edge : g[i]) {
                int j; ll d; tie(j, d) = edge;
                if (dist[j] + d != dist[i]) continue;
                acc += cnt[j];
            }
            cnt[i] = acc % mod;
        }
    }
    return cnt;
}

int main() {
    // input
    int n, m; scanf("%d%d", &n, &m);
    int s, t; scanf("%d%d", &s, &t);
    -- s; -- t;

    vector<vector<pair<int, ll> > > g(n);
    REP (i, m) {
        int u, v, d; scanf("%d%d%d", &u, &v, &d);
        -- u; -- v;
        g[u].emplace_back(v, d);
        g[v].emplace_back(u, d);
    }

    // solve
    vector<ll> dist_from_s = dijkstra(g, s);
    vector<ll> dist_to_t   = dijkstra(g, t);
    vector<int> count_from_s = count_path(g, s, dist_from_s);
    vector<int> count_to_t   = count_path(g, t, dist_to_t);
    auto used = [&](int i) { return dist_from_s[i] + dist_to_t[i] == dist_from_s[t]; };

    ll complement = 0;
    REP (i, n) {
        if (not used(i)) continue;
        if (dist_from_s[i] == dist_to_t[i]) {
            complement += sq(count_from_s[i]) * sq(count_to_t[i]) % mod;
        }
        for (auto edge : g[i]) {
            int j; ll dist; tie(j, dist) = edge;
            if (dist_from_s[i] + dist != dist_from_s[j]) continue;
            if (not used(j)) continue;
            if (dist_from_s[i] < dist_from_s[t] / 2.0 and dist_to_t[j] < dist_from_s[t] / 2.0) {
                complement += sq(count_from_s[i]) * sq(count_to_t[j]) % mod;
            }
        }
    }
    complement %= mod;
    int result = (sq(count_from_s[t]) - complement + mod) % mod;

    // output
    printf("%d\n", result);
    return 0;
}
```
