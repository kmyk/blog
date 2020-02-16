---
layout: post
date: 2018-08-06T20:26:00+09:00
tags: [ "competitive", "writeup", "atcoder", "euler-tour", "segment-tree", "random" ]
"target_url": [ "https://beta.atcoder.jp/contests/njpc2017/tasks/njpc2017_h" ]
---

# NJPC2017: H - 白黒ツリー

## solution

親と子の色が一致してしまっている個数を上手く管理。
重軽分解して無理矢理やればできるはず。
しかしEuler tourして点更新/区間和のsegment treeで十分。
$O((n + q) \log n)$。

Euler tourは行きと帰りで両方追加するもの。
行きの重みと帰りの重みが上手く相殺されるように乗せればよい。
ここ重みは$+1, -1$で算術の和をとれば十分だがLCAして2回の区間和が必要。
重みを乱数で生成し排他的論理和でまとめればLCAなしの1回の区間和で済む。
ただし確率的には衝突しうることに注意。

## note

重軽分解をEuler tourで置き換えられる条件は何だろうか。
点更新と$x + x = 0$な操作に関する区間和のsegment treeが乗ってることな気がする。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < (int)(n); ++ (i))
#define REP_R(i, n) for (int i = int(n) - 1; (i) >= 0; -- (i))
using namespace std;

/**
 * @brief euler tour
 * @arg g must be a tree, directed or undirected
 */
void do_euler_tour(vector<vector<int> > const & g, int root, vector<int> & tour, vector<int> & left, vector<int> & right) {
    int n = g.size();
    tour.clear();
    left.resize(n);
    right.resize(n);
    function<void (int, int)> go = [&](int x, int parent) {
        left[x] = tour.size();
        tour.push_back(x);
        for (int y : g[x]) if (y != parent) {
            go(y, x);
        }
        right[x] = tour.size();
        tour.push_back(x);
    };
    go(root, -1);
}

/**
 * @brief a segment tree, or a fenwick tree
 * @tparam Monoid (commutativity is not required)
 */
template <class Monoid>
struct segment_tree {
    typedef typename Monoid::underlying_type underlying_type;
    int n;
    vector<underlying_type> a;
    Monoid mon;
    segment_tree() = default;
    segment_tree(int a_n, underlying_type initial_value = Monoid().unit(), Monoid const & a_mon = Monoid()) : mon(a_mon) {
        n = 1; while (n < a_n) n *= 2;
        a.resize(2 * n - 1, mon.unit());
        fill(a.begin() + (n - 1), a.begin() + ((n - 1) + a_n), initial_value); // set initial values
        REP_R (i, n - 1) a[i] = mon.append(a[2 * i + 1], a[2 * i + 2]); // propagate initial values
    }
    void point_set(int i, underlying_type z) { // 0-based
        assert (0 <= i and i <= n);
        a[i + n - 1] = z;
        for (i = (i + n) / 2; i > 0; i /= 2) { // 1-based
            a[i - 1] = mon.append(a[2 * i - 1], a[2 * i]);
        }
    }
    underlying_type range_concat(int l, int r) { // 0-based, [l, r)
        assert (0 <= l and l <= r and r <= n);
        underlying_type lacc = mon.unit(), racc = mon.unit();
        for (l += n, r += n; l < r; l /= 2, r /= 2) { // 1-based loop, 2x faster than recursion
            if (l % 2 == 1) lacc = mon.append(lacc, a[(l ++) - 1]);
            if (r % 2 == 1) racc = mon.append(a[(-- r) - 1], racc);
        }
        return mon.append(lacc, racc);
    }
};
struct xor_monoid {
    typedef uint64_t underlying_type;
    uint64_t unit() const { return 0; }
    uint64_t append(uint64_t a, uint64_t b) const { return a ^ b; }
};

class solver {
    static constexpr int root = 0;
    vector<bool> delta;
    vector<uint64_t> id;
    vector<int> tour, left, right;
    segment_tree<xor_monoid> segtree;

public:
    solver(int n, vector<int> const & parent, vector<vector<int> > const & children, vector<bool> const & c) {
        mt19937_64 gen;
        id.resize(n);
        delta.resize(n);
        REP (x, n) {
            id[x] = uniform_int_distribution<uint64_t>()(gen);
            if (x != root) {
                delta[x] = c[x] == c[parent[x]];
            }
        }

        do_euler_tour(children, root, tour, left, right);

        segtree = segment_tree<xor_monoid>(tour.size());
        REP (i, tour.size()) {
            int x = tour[i];
            segtree.point_set(i, delta[x] ? id[x] : 0);
        }
    }

    void query_op(int x) {
        if (x == 0) return;
        delta[x] = not delta[x];
        segtree.point_set( left[x], delta[x] ? id[x] : 0);
        segtree.point_set(right[x], delta[x] ? id[x] : 0);
    }

    bool query_ans(int x, int y) {
        if (left[x] > left[y]) swap(x, y);
        return segtree.range_concat(left[x] + 1, left[y] + 1) == 0;
    }
};

int main() {
    // input
    int n; cin >> n;
    vector<int> parent(n);
    vector<vector<int> > children(n);
    parent[0] = -1;
    REP3 (i, 1, n) {
        cin >> parent[i];
        -- parent[i];
        children[parent[i]].push_back(i);
    }
    vector<bool> c(n);
    REP (i, n) {
        int c_i; cin >> c_i;
        c[i] = c_i;
    }

    // solve
    solver s(n, parent, children, c);

    // output
    int q; cin >> q;
    while (q --) {
        int t; cin >> t;
        if (t == 1) {
            int u; cin >> u;
            -- u;
            s.query_op(u);
        } else if (t == 2) {
            int u, v; cin >> u >> v;
            -- u; -- v;
            bool ans = s.query_ans(u, v);
            cout << (ans ? "YES" : "NO") << endl;
        }
    }
    return 0;
}
```
