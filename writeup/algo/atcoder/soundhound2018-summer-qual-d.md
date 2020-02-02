---
layout: post
title: "SoundHound Inc. Programming Contest 2018 -Masters Tournament-: D - Saving Snuuk"
date: 2018-07-07T23:53:09+09:00
tags: [ "competitive", "writeup", "atcoder", "dijkstra" ]
"target_url": [ "https://beta.atcoder.jp/contests/soundhound2018-summer-qual/tasks/soundhound2018_summer_qual_d" ]
---

## solution

途中で1回だけグラフが切り替わるので、両側からDijkstra (典型)。 $O(V \log E)$。

## note

何かを勘違いしてとても時間をかけた。以下の実装に無駄に一般化されたdijkstraが貼ってあるのはそのため

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define REP_R(i, n) for (int i = int(n) - 1; (i) >= 0; -- (i))
using ll = long long;
using namespace std;
template <class T> inline void chmin(T & a, T const & b) { a = min(a, b); }

template <class Weight, class Func>
void generic_dijkstra(int root, vector<Weight> & dist, Func iterate_adjacent_vertices) {
    dist.assign(dist.size(), numeric_limits<Weight>::max());
    priority_queue<pair<Weight, int> > que;
    dist[root] = 0;
    que.emplace(- dist[root], root);
    while (not que.empty()) {
        Weight dist_i; int i; tie(dist_i, i) = que.top(); que.pop();
        if (dist[i] < - dist_i) continue;
        iterate_adjacent_vertices(i, [&](int j, Weight cost) {
            if (- dist_i + cost < dist[j]) {
                dist[j] = - dist_i + cost;
                que.emplace(dist_i - cost, j);
            }
        });
    }
}

int main() {
    // input
    int n, m, s, t;
    cin >> n >> m >> s >> t;
    -- s; -- t;
    vector<vector<tuple<int, int, int> > > g(n);
    REP (i, m) {
        int u, v, a, b;
        cin >> u >> v >> a >> b;
        -- u; -- v;
        g[u].emplace_back(v, a, b);
        g[v].emplace_back(u, a, b);
    }

    // solve
    vector<ll> dist1(n);
    generic_dijkstra<ll>(s, dist1, [&](int i, auto cont) {
        for (auto edge : g[i]) {
            int j, a; tie(j, a, ignore) = edge;
            cont(j, a);
        }
    });

    vector<ll> dist2(n);
    generic_dijkstra<ll>(t, dist2, [&](int i, auto cont) {
        for (auto edge : g[i]) {
            int j, b; tie(j, ignore, b) = edge;
            cont(j, b);
        }
    });

    vector<ll> ans(n);
    REP (i, n) {
        ans[i] = dist1[i] + dist2[i];
    }
    REP_R (i, n - 1) {
        chmin(ans[i], ans[i + 1]);
    }

    // output
    REP (i, n) {
        cout << 1000000000000000ll - ans[i] << endl;
    }
    return 0;
}
```
