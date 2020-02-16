---
layout: post
date: 2018-09-14T01:41:11+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "binary-search", "minimum-spanning-tree" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc026/tasks/arc026_4" ]
---

# AtCoder Regular Contest 026: D - 道を直すお仕事

## 解法

二分探索。最小全域木。$$N \le M$$として$$O(M \log M \cdot \log \max C_i)$$。

グラフを連結にする$$E' \subseteq E$$の中での$$\sum _ {i \in E} C_i / \sum _ {i \in E} T_i$$の最小値を求める問題。
この答えの値を二分探索。
仮にこれを$a$と置くと $$\sum _ {i \in E} C_i - a \sum _ {i \in E} T_i$$ を最小化する問題になって、これは通常の最小全域木問題とほぼ同様に解ける。
不要な辺でも重みが負なら使う点のみが差分。
そうして得られた値$a'$と仮に置いた値$a$の大小を比較すれば、真の値が$a$より大きいか小さいかが分かる。

## メモ

-   ARCのDにしては簡単 600点ぐらい
-   必要十分なコストの形がよく分からない。線形ならというわけではなく、すべての重みの総乗を最小化とかでも同様にできるなどがある

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define ALL(x) begin(x), end(x)
using ll = long long;
using namespace std;

struct union_find_tree {
    vector<int> data;
    union_find_tree() = default;
    explicit union_find_tree(size_t n) : data(n, -1) {}
    bool is_root(int i) { return data[i] < 0; }
    int find_root(int i) { return is_root(i) ? i : (data[i] = find_root(data[i])); }
    int tree_size(int i) { return - data[find_root(i)]; }
    int unite_trees(int i, int j) {
        i = find_root(i); j = find_root(j);
        if (i != j) {
            if (tree_size(i) < tree_size(j)) swap(i,j);
            data[i] += data[j];
            data[j] = i;
        }
        return i;
    }
    bool is_same(int i, int j) { return find_root(i) == find_root(j); }
};

template <typename UnaryPredicate>
double binsearch_float(double l, double r, UnaryPredicate p) {
    assert (l <= r);
    REP (iteration, 100) {
        double m = (l + r) / 2;
        (p(m) ? r : l) = m;
    }
    return r;
}


struct edge_t { int u, v, num, den; };

// Kruskal's method
pair<ll, ll> minimum_spanning_tree(int n, vector<edge_t> & edges, double ans) {
    sort(ALL(edges), [&](edge_t const & a, edge_t const & b) {
        return (a.num - ans * a.den) < (b.num - ans * b.den);
    });
    ll num = 0;
    ll den = 0;
    union_find_tree uft(n);
    for (auto e : edges) {
        if (e.num < ans * e.den or not uft.is_same(e.u, e.v)) {
            uft.unite_trees(e.u, e.v);
            num += e.num;
            den += e.den;
        }
    }
    return make_pair(num, den);
}

double solve(int n, int m, vector<edge_t> & edges) {
    return binsearch_float(0, 1e6, [&](double ans) {
        ll num, den; tie(num, den) = minimum_spanning_tree(n, edges, ans);
        return num < ans * den;
    });
}

int main() {
    int n, m; cin >> n >> m;
    vector<edge_t> edges(m);
    REP (i, m) {
        int a, b, c, t; cin >> a >> b >> c >> t;
        edges[i] = { a, b, c, t };
    }
    double ans = solve(n, m, edges);
    printf("%.12lf\n", ans);
    return 0;
}
```
