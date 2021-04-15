---
layout: post
redirect_from:
  - /writeup/algo/atcoder/code-festival-2016-asapro-1-a/
  - /blog/2016/11/30/code-festival-2016-asapro-1-a/
date: "2016-11-30T13:42:26+09:00"
tags: [ "competitive", "writeup", "atcoder", "codefestival", "minimum-spanning-tree" ]
"target_url": [ "https://beta.atcoder.jp/contests/cf16-tournament-round1-open/tasks/asaporo_c" ]
---

# CODE FESTIVAL 2016 Elimination Tournament Round 1: A - グラフ / Graph

最小全域木のライブラリがなかった(ないということも気付いてなかった)ため、Bを先にやったのと合わせて本番間に合わず。

$s-t$間に重み$0$の辺を張る部分点解法もあるらしい。全完解法より頭がいいように感じる。

## solution

全体の最小全域木$T$をまず求め、各クエリ$(s, t)$ごとに$T$上の$(s,t)$-path中の最大重みの辺を切ればよい。
$Q \le 100000$だが$N^2$かけて前処理しておけば$O(M \log M + N^2 + Q)$。
毎回$(s,t)$-pathを計算すれば$O(M \log M + QN)$となり部分点だろう。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <functional>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
typedef long long ll;
using namespace std;
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }

struct disjoint_sets {
    vector<int> xs;
    disjoint_sets() = default;
    explicit disjoint_sets(size_t n) : xs(n, -1) {}
    bool is_root(int i) { return xs[i] < 0; }
    int find_root(int i) { return is_root(i) ? i : (xs[i] = find_root(xs[i])); }
    int set_size(int i) { return - xs[find_root(i)]; }
    int union_sets(int i, int j) {
        i = find_root(i); j = find_root(j);
        if (i != j) {
            if (set_size(i) < set_size(j)) swap(i,j);
            xs[i] += xs[j];
            xs[j] = i;
        }
        return i;
    }
    bool is_same(int i, int j) { return find_root(i) == find_root(j); }
};
template <typename T> struct weighted_edge_t { int u, v; T w; };
template <typename T> bool operator < (weighted_edge_t<T> const & a, weighted_edge_t<T> const & b) { return make_tuple(a.w, a.u, a.v) < make_tuple(b.w, b.u, b.v); }
template <typename T>
vector<vector<weighted_edge_t<T> > > minimum_spanning_tree(int n, vector<weighted_edge_t<T> > edges) { // Kruskal's method, O(E \log E)
    vector<vector<weighted_edge_t<T> > > tree(n);
    disjoint_sets sets(n);
    whole(sort, edges);
    for (auto e : edges) {
        if (not sets.is_same(e.u, e.v)) {
            sets.union_sets(e.u, e.v);
            tree[e.u].push_back( (weighted_edge_t<T>) { e.u, e.v, e.w } );
            tree[e.v].push_back( (weighted_edge_t<T>) { e.v, e.u, e.w } );
        }
    }
    return tree;
}

int main() {
    int n, m; cin >> n >> m;
    vector<weighted_edge_t<int> > es(m);
    repeat (i,m) {
        int a, b, c; cin >> a >> b >> c; -- a; -- b;
        es[i] = { a, b, c };
    }
    auto mst = minimum_spanning_tree(n, es);
    ll total = 0;
    repeat (i,n) for (auto e : mst[i]) {
        if (e.u < e.v) total += e.w;
    }
    vector<vector<int> > drop = vectors(n, n, int()); {
        repeat (i,n) {
            function<void (int, int)> dfs = [&](int j, int parent) {
                for (auto e : mst[j]) if (e.v != parent) {
                    drop[i][e.v] = max(drop[i][j], e.w);
                    dfs(e.v, j);
                }
            };
            drop[i][i] = 0;
            dfs(i, i);
        }
    }
    int q; cin >> q;
    while (q --) {
        int s, t; cin >> s >> t; -- s; -- t;
        cout << total - drop[s][t] << endl;
    }
    return 0;
}
```
