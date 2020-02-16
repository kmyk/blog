---
layout: post
redirect_from:
  - /blog/2018/04/02/aoj-ritscamp18day3-e/
date: "2018-04-02T22:46:51+09:00"
tags: [ "competitive", "writeup", "aoj", "rupc", "tree", "euler-tour", "segment-tree" ]
"target_url": [ "https://onlinejudge.u-aizu.ac.jp/beta/room.html#RitsCamp18Day3/problems/E" ]
---

# AOJ RitsCamp18Day3: E. ブロッコリー？カリフラワー？ (Broccoli or Cauliflower)

## solution

Euler tourして遅延評価segment木。$O((n + q) \log n)$。
遅延評価segment木に乗せるのは、区間中の緑の頂点の数と白の頂点の数をそれぞれ数えるクエリと、区間中の緑と白を反転させるクエリ。

## note

-   見てすぐ「二分木をポインタ使って書けばいいじゃん」とか言ってたけど大嘘だった
-   出力するのを「対象になった部分木がブロッコリー/カリフラワー」だと誤読した。サンプルに救われた

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < int(n); ++ (i))
#define REP_R(i, n) for (int i = int(n) - 1; (i) >= 0; -- (i))
using namespace std;

void do_left_euler_tour(vector<vector<int> > const & g, int root, vector<int> & tour, vector<int> & left, vector<int> & right) {
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
    };
    go(root, -1);
}

template <class Monoid, class OperatorMonoid>
struct lazy_propagation_segment_tree { // on monoids
    static_assert (is_same<typename Monoid::underlying_type, typename OperatorMonoid::target_type>::value, "");
    typedef typename Monoid::underlying_type underlying_type;
    typedef typename OperatorMonoid::underlying_type operator_type;
    const Monoid mon;
    const OperatorMonoid op;
    int n;
    vector<underlying_type> a;
    vector<operator_type> f;
    lazy_propagation_segment_tree() = default;
    lazy_propagation_segment_tree(int a_n, underlying_type initial_value = Monoid().unit(), Monoid const & a_mon = Monoid(), OperatorMonoid const & a_op = OperatorMonoid())
            : mon(a_mon), op(a_op) {
        n = 1; while (n <= a_n) n *= 2;
        a.resize(2 * n - 1, mon.unit());
        fill(a.begin() + (n - 1), a.begin() + ((n - 1) + a_n), initial_value); // set initial values
        REP_R (i, n - 1) a[i] = mon.append(a[2 * i + 1], a[2 * i + 2]); // propagate initial values
        f.resize(max(0, (2 * n - 1) - n), op.identity());
    }
    void point_set(int i, underlying_type z) {
        assert (0 <= i and i < n);
        point_set(0, 0, n, i, z);
    }
    void point_set(int i, int il, int ir, int j, underlying_type z) {
        if (i == n + j - 1) { // 0-based
            a[i] = z;
        } else if (ir <= j or j+1 <= il) {
            // nop
        } else {
            range_apply(2 * i + 1, il, (il + ir) / 2, 0, n, f[i]);
            range_apply(2 * i + 2, (il + ir) / 2, ir, 0, n, f[i]);
            f[i] = op.identity();
            point_set(2 * i + 1, il, (il + ir) / 2, j, z);
            point_set(2 * i + 2, (il + ir) / 2, ir, j, z);
            a[i] = mon.append(a[2 * i + 1], a[2 * i + 2]);
        }
    }
    void range_apply(int l, int r, operator_type z) {
        assert (0 <= l and l <= r and r <= n);
        range_apply(0, 0, n, l, r, z);
    }
    void range_apply(int i, int il, int ir, int l, int r, operator_type z) {
        if (l <= il and ir <= r) { // 0-based
            a[i] = op.apply(z, a[i]);
            if (i < f.size()) f[i] = op.compose(z, f[i]);
        } else if (ir <= l or r <= il) {
            // nop
        } else {
            range_apply(2 * i + 1, il, (il + ir) / 2, 0, n, f[i]);
            range_apply(2 * i + 2, (il + ir) / 2, ir, 0, n, f[i]);
            f[i] = op.identity();
            range_apply(2 * i + 1, il, (il + ir) / 2, l, r, z);
            range_apply(2 * i + 2, (il + ir) / 2, ir, l, r, z);
            a[i] = mon.append(a[2 * i + 1], a[2 * i + 2]);
        }
    }
    underlying_type range_concat(int l, int r) {
        assert (0 <= l and l <= r and r <= n);
        return range_concat(0, 0, n, l, r);
    }
    underlying_type range_concat(int i, int il, int ir, int l, int r) {
        if (l <= il and ir <= r) { // 0-based
            return a[i];
        } else if (ir <= l or r <= il) {
            return mon.unit();
        } else {
            return op.apply(f[i], mon.append(
                    range_concat(2 * i + 1, il, (il + ir) / 2, l, r),
                    range_concat(2 * i + 2, (il + ir) / 2, ir, l, r)));
        }
    }
};

struct ratio_monoid {
    typedef pair<int, int> underlying_type;
    underlying_type unit() const { return make_pair(0, 0); }
    underlying_type append(underlying_type a, underlying_type b) const {
        return make_pair(a.first + b.first, a.second + b.second);
    }
};
struct reverse_operator_monoid {
    typedef bool underlying_type;
    typedef ratio_monoid::underlying_type target_type;
    underlying_type identity() const { return false; }
    target_type apply(underlying_type a, target_type b) const {
        return a ? make_pair(b.second - b.first, b.second) : b;
    }
    underlying_type compose(underlying_type a, underlying_type b) const { return a != b; }
};

constexpr int root = 0;
int main() {
    // input
    int n, q; cin >> n >> q;
    vector<int> parent(n);
    parent[root] = -1;
    REP (i, n - 1) {
        cin >> parent[i + 1];
        -- parent[i + 1];
    }
    vector<bool> state(n);  // true if broccoli
    REP (i, n) {
        char c; cin >> c;
        state[i] = (c == 'G');
    }

    // solve
    vector<vector<int> > children(n);
    REP3 (i, 1, n) {
        children[parent[i]].push_back(i);
    }
    vector<int> tour, left, right;
    do_left_euler_tour(children, root, tour, left, right);
    lazy_propagation_segment_tree<ratio_monoid, reverse_operator_monoid> segtree(n);
    REP (i, n) {
        segtree.point_set(i, make_pair(state[tour[i]], 1));
    }

    // output
    while (q --) {
        int subtree; cin >> subtree;
        -- subtree;
        segtree.range_apply(left[subtree], right[subtree], true);
        int num, den; tie(num, den) = segtree.range_concat(0, n);
        cout << (num > den / 2 ? "broccoli" : "cauliflower") << endl;
    }
    return 0;
}
```
