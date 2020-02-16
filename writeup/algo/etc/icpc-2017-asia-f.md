---
layout: post
redirect_from:
  - /blog/2017/12/19/icpc-2017-asia-f/
date: "2017-12-19T03:49:21+09:00"
tags: [ "competitive", "writeup", "icpc", "icpc-asia", "graph", "digraph", "dijkstra", "two-edge-connected-components" ]
---

# AOJ 1383 / ACM-ICPC 2017 Asia Tsukuba Regional Contest: F. Pizza Delivery

-   <http://judge.u-aizu.ac.jp/onlinejudge/description.jsp?id=1383>
-   <http://judge.u-aizu.ac.jp/onlinejudge/cdescription.jsp?cid=ICPCOOC2017&pid=F>

## problem

辺重み付き有向グラフ$G$が与えられる。それぞれの有向辺についてその向きを逆にしたときに$S \to T$最短路はどう変化するか(短くなる/変らない/長くなる)答えよ。

## solution

両側からDijkstra。$S \to T$最短路の成すDAGを無向グラフと見て二重辺連結成分分解。$O((E + V) \log V)$。

有向辺$e = (a \to b \text{with cost} c)$をとる。
$\mathrm{d}(S, b) + c + \mathrm{d}(a, T)$と$\mathrm{d}(S, T)$を比較し、短くなるあるいは変化しないならそれがそのまま答え。そうでない、つまりその辺を使うような$S \to T$有向路が長くなると仮定する。
$\mathrm{d}(S, a) + c + \mathrm{d}(b, T) = \mathrm{d}(S, T)$であれば元々の最短路中に含まれる辺であり、そうでなければそうでない。元々の最短路中に含まれてなければ長くなっても変わらない。含まれていると仮定する。そうなると辺$e$を使わない$S \to T$最短路が存在するかどうかが答えとなる。
これは$e$が$S \to T$最短路の成すグラフの橋であるかどうかと同じ。これは二重辺連結成分分解で求まる。

注意すべきは$S \to T$最短路の成すグラフの構成。余分な辺を入れてはいけない。
多重辺があるかもしれないことにも注意。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
using ll = long long;
using namespace std;

constexpr ll inf = ll(1e18) + 9;

vector<ll> dijkstra(vector<vector<pair<int, ll> > > const & g, int root) {
    vector<ll> dist(g.size(), inf);
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

pair<int, vector<int> > decompose_to_two_edge_connected_components(vector<vector<int> > const & g) {
    int n = g.size();
    vector<int> imos(n); { // imos[i] == 0  iff  the edge i -> parent is a bridge
        vector<char> used(n); // 0: unused ; 1: exists on stack ; 2: removed from stack
        function<void (int, int)> go = [&](int i, int parent) {
            used[i] = 1;
            for (int j : g[i]) if (j != parent) {
                if (used[j] == 0) {
                    go(j, i);
                    imos[i] += imos[j];
                } else if (used[j] == 1) {
                    imos[i] += 1;
                    imos[j] -= 1;
                }
            }
            used[i] = 2;
        };
        REP (i, n) if (used[i] == 0) {
            go(i, -1);
        }
    }
    int size = 0;
    vector<int> component_of(n, -1); {
        function<void (int)> go = [&](int i) {
            for (int j : g[i]) if (component_of[j] == -1) {
                component_of[j] = imos[j] == 0 ? size ++ : component_of[i];
                go(j);
            }
        };
        REP (i, n) if (component_of[i] == -1) {
            component_of[i] = size ++;
            go(i);
        }
    }
    return { size, move(component_of) };
}

enum result_t { HAPPY, SOSO, SAD };
constexpr int start = 0;
constexpr int goal = 1;
int main() {
    // input
    int n, m; scanf("%d%d", &n, &m);
    vector<tuple<int, int, int> > edges(m);
    REP (i, m) {
        int a, b, c; scanf("%d%d%d", &a, &b, &c);
        -- a; -- b;
        edges[i] = make_tuple(a, b, c);
    }
    // solve
    vector<vector<pair<int, ll >> > g(n);
    vector<vector<pair<int, ll >> > rev_g(n);
    map<tuple<int, int, int>, int> count_edges;
    for (auto edge : edges) {
        int a, b, c; tie(a, b, c) = edge;
        g[a].emplace_back(b, c);
        rev_g[b].emplace_back(a, c);
        count_edges[edge] += 1;
    }
    auto dist = dijkstra(g, start);
    auto rev_dist = dijkstra(rev_g, goal);
    vector<vector<int> > h(n);
    REP (i, n) {
        for (auto edge : g[i]) {
            int j, cost; tie(j, cost) = edge;
            if (dist[i] + cost + rev_dist[j] == dist[goal]) {
                h[i].push_back(j);
                h[j].push_back(i);
            }
        }
    }
    auto component_of = decompose_to_two_edge_connected_components(h).second;
    // output
    for (auto edge : edges) {
        int a, b, c; tie(a, b, c) = edge;
        result_t result =
            dist[b] + c + rev_dist[a] <  dist[goal] ? HAPPY :
            dist[b] + c + rev_dist[a] == dist[goal] ? SOSO :
            dist[a] + c + rev_dist[b] != dist[goal] ? SOSO :
            count_edges[edge] >= 2 ? SOSO :
            component_of[a] != component_of[b] ? SAD :
            SOSO;
        printf("%s\n",
            result == HAPPY ? "HAPPY" :
            result == SOSO ? "SOSO" :
            result == SAD ? "SAD" :
            "");
    }
    return 0;
}
```
