---
layout: post
alias: "/blog/2017/12/29/utpc2011-k/"
title: "東京大学プログラミングコンテスト2011: K. 巡回セールスマン問題"
date: "2017-12-29T07:48:35+09:00"
tags: [ "competitive", "writeup", "utpc", "aoj", "graph", "dijkstra", "warshall-floyd", "lowest-common-ancestor", "sparse-table", "optimization" ]
---

-   <http://www.utpc.jp/2011/problems/travel.html>
-   <http://judge.u-aizu.ac.jp/onlinejudge/description.jsp?id=2269>

AtCoderに提出したらなぜかテストケースが$0$個で自明なACが出る状態になってた。

## solution

ほとんど木なので上手くやる。荒く見積もって$O(M \log N + (M - N)^3 + N^2)$。

$\|E\| \le \|V\| + 500$という制約によりほとんど木である。
頂点$1$を根として最短経路による木を張り、高々$501$本ある余った辺を覚えておく。
そのような辺の始点と終点は高々$1002$点であり、これに頂点$1$を加え、他の頂点と区別しておく。
そのような頂点のみで全点対間の最短距離を求める。
この情報ともに$1, 2, 3, \dots$と巡回をする。
頂点$i$から$i+1$へ移動するときには、$i$の下側の近い区別された頂点から$i+1$の上側の一番近い区別された頂点へ、あらかじめ求めておいた最短距離で移動するとすればよい。
上側の頂点は一意だが下側の頂点は一意ではないので、これは間に合うことを信じて全て全て舐める。


注意:

-   巡回は可能だとは限らないのでだめな場合は適当に落とす
-   多重辺はありうるので潰しておく
-   LCAで$O(\log N)$が乗ると間に合わないので <https://www.slideshare.net/yumainoue965/lca-and-rmq> を読んで$O(1)$を書く
-   上のように理解をして通しはしたが何か勘違いしてそう。下側の区別された頂点も一意だったのでは

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define ALL(x) begin(x), end(x)
using ll = long long;
using namespace std;
template <class T> inline void chmin(T & a, T const & b) { a = min(a, b); }

vector<int> dijkstra(vector<vector<pair<int, int> > > const & g, int root) {
    vector<int> dist(g.size(), INT_MAX);
    priority_queue<pair<int, int> > que;
    dist[root] = 0;
    que.emplace(- dist[root], root);
    while (not que.empty()) {
        int dist_i; int i; tie(dist_i, i) = que.top(); que.pop();
        if (dist[i] < - dist_i) continue;
        for (auto it : g[i]) {
            int j; int cost; tie(j, cost) = it;
            if (- dist_i + cost < dist[j]) {
                dist[j] = - dist_i + cost;
                que.emplace(dist_i - cost, j);
            }
        }
    }
    return dist;
}

vector<vector<int> > warshall_floyd(vector<vector<pair<int, int> > > const & g) {
    int n = g.size();
    vector<vector<int> > dist(n, vector<int>(n, INT_MAX));
    REP (i, n) {
        dist[i][i] = 0;
        for (auto edge : g[i]) {
            int j, cost; tie(j, cost) = edge;
            dist[i][j] = cost;
        }
    }
    REP (k, n) {
        REP (i, n) if (dist[i][k] != INT_MAX) {
            REP (j, n) if (dist[k][j] != INT_MAX) {
                chmin(dist[i][j], dist[i][k] + dist[k][j]);
            }
        }
    }
    return dist;
}

template <class Monoid>
struct sparse_table {
    typedef typename Monoid::underlying_type underlying_type;
    vector<vector<underlying_type> > table;
    Monoid mon;
    sparse_table() = default;
    sparse_table(vector<underlying_type> const & data, Monoid const & a_mon = Monoid())
            : mon(a_mon) {
        int n = data.size();
        int log_n = 32 - __builtin_clz(n);
        table.resize(log_n, vector<underlying_type>(n, mon.unit()));
        table[0] = data;
        for (int k = 0; k < log_n-1; ++ k) {
            for (int i = 0; i < n; ++ i) {
                table[k+1][i] = mon.append(table[k][i], i + (1ll<<k) < n ? table[k][i + (1ll<<k)] : mon.unit());
            }
        }
    }
    underlying_type range_concat(int l, int r) const {
        assert (0 <= l and l <= r and r <= table[0].size());
        if (l == r) return mon.unit();
        int k = 31 - __builtin_clz(r - l);  // log2
        return mon.append(table[k][l], table[k][r - (1ll<<k)]);
    }
};
struct indexed_min_monoid {
    typedef pair<int, int> underlying_type;
    underlying_type unit() const { return { INT_MAX, INT_MAX }; }
    underlying_type append(underlying_type a, underlying_type b) const { return min(a, b); }
};
struct lowest_common_ancestor {
    sparse_table<indexed_min_monoid> table;
    vector<int> index;
    lowest_common_ancestor() = default;
    lowest_common_ancestor(int root, vector<vector<int> > const & g) {
        vector<pair<int, int> > tour;
        index.assign(g.size(), -1);
        function<void (int, int, int)> go = [&](int i, int parent, int depth) {
            index[i] = tour.size();
            tour.emplace_back(depth, i);
            for (int j : g[i]) if (j != parent) {
                go(j, i, depth + 1);
                tour.emplace_back(depth, i);
            }
        };
        go(root, -1, 0);
        table = sparse_table<indexed_min_monoid>(tour);
    }
    int operator () (int x, int y) const {
        x = index[x];
        y = index[y];
        if (x > y) swap(x, y);
        return table.range_concat(x, y + 1).second;
    }
};

ll solve(int n, int m, vector<vector<pair<int, int> > > & g) {

    // erase duplicated edges
    REP (i, n) {
        sort(ALL(g[i]));
        g[i].erase(unique(ALL(g[i]), [&](pair<int, int> e1, pair<int, int> e2) {
            return e1.first == e2.first;
        }), g[i].end());
    }

    // calculate shortest-paths and check the possibility
    constexpr int root = 0;
    vector<int> dist_root = dijkstra(g, root);
    if (count(ALL(dist_root), INT_MAX)) {
        return -1;
    }
    vector<vector<pair<int, int> > > rev_g(n);
    REP (i, n) {
        for (auto edge : g[i]) {
            int j, cost; tie(j, cost) = edge;
            rev_g[j].emplace_back(i, cost);
        }
    }
    auto rev_dist_root = dijkstra(rev_g, root);
    if (count(ALL(rev_dist_root), INT_MAX)) {
        return -1;
    }

    // make a shortest-path tree; collect the unused edges
    vector<vector<int> > children(n);
    vector<int> parent(n, -1);
    vector<vector<pair<int, int> > > unused_edges(n);
    REP (i, n) {
        for (auto edge : g[i]) {
            int j, cost; tie(j, cost) = edge;
            if (dist_root[i] + cost == dist_root[j] and parent[j] == -1) {
                children[i].push_back(j);
                parent[j] = i;
            } else {
                unused_edges[i].emplace_back(j, cost);
            }
        }
    }

    // select and reorder distinguished vertices
    map<int, int> distinguished;
    auto distinguished_insert = [&](int i) {
        if (not distinguished.count(i)) {
            distinguished.emplace(i, distinguished.size());
        }
    };
    distinguished_insert(0);
    REP (i, n) {
        if (not unused_edges[i].empty()) {
            distinguished_insert(i);
        }
        for (auto edge : unused_edges[i]) {
            int j = edge.first;
            distinguished_insert(j);
        }
    }

    // compute distances for all distinguished vertices; find the lowest distinguished ancestors for each vertex
    vector<vector<pair<int, int> > > h(distinguished.size());
    REP (i, n) {
        for (auto edge : unused_edges[i]) {
            int j, cost; tie(j, cost) = edge;
            h[distinguished[i]].emplace_back(distinguished[j], cost);
        }
    }
    vector<int> ancestor(n, -1);
    function<void (int, int)> go = [&](int i, int last) {
        if (distinguished.count(i)) {
            if (last != -1) {
                h[distinguished[last]].emplace_back(distinguished[i], dist_root[i] - dist_root[last]);
            }
            last = i;
        }
        ancestor[i] = last;
        for (int j : children[i]) {
            go(j, last);
        }
    };
    go(root, -1);
    auto dist = warshall_floyd(h);

    // prepare the lca for the shortest-path tree
    lowest_common_ancestor lca(root, children);

    // compute the result
    ll result = 0;
    REP (i, n) {
        int j = (i + 1) % n;
        if (lca(i, j) == i) {
            result += dist_root[j] - dist_root[i];
        } else {
            int acc = INT_MAX;
            for (auto it : distinguished) {
                int k, distinguished_k; tie(k, distinguished_k) = it;
                if (lca(i, k) == i) {
                    chmin(acc, (dist_root[k] - dist_root[i]) + dist[distinguished_k][distinguished[ancestor[j]]] + (dist_root[j] - dist_root[ancestor[j]]));
                }
            }
            result += acc;
        }
    }

    return result;
}

int main() {
    // input
    int n, m; scanf("%d%d", &n, &m);
    vector<vector<pair<int, int> > > g(n);
    REP (i, m) {
        int a, b, c; scanf("%d%d%d", &a, &b, &c);
        -- a; -- b;
        g[a].emplace_back(b, c);
    }
    // solve
    ll result = solve(n, m, g);
    // output
    printf("%lld\n", result);
    return 0;
}
```
