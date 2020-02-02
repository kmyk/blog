---
layout: post
alias: "/blog/2018/01/15/arc-085-f/"
title: "AtCoder Regular Contest 085: F - NRE"
date: "2018-01-15T15:32:19+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "dp", "segment-tree", "lazy-propagation" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc085/tasks/arc085_d" ]
---

## solution

DP。単純には$l\_j$の小さい順に$i$番目の操作まで使って位置$l\_i$以降は位置$j$まで全て$1$に書き変わっているときの位置$j$までの範囲のHamming距離の最小値を$\mathrm{dp}(i, j)$とする。
このままでは$O(NQ)$で間に合わないので、数列$a$中における位置$j$までの$0$の数を$z(j)$としてこれを引いた$\mathrm{dp}(i, j) - z(j)$を区間加算と区間最小値の遅延伝播segment木を用いて管理し上手くやる。
つまり実家。$O(Q \log N)$。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define REP_R(i, n) for (int i = int(n) - 1; (i) >= 0; -- (i))
using namespace std;

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


constexpr int inf = 1e9 + 7;
struct min_monoid {
    typedef int underlying_type;
    int unit() const { return inf; }
    int append(int a, int b) const { return min(a, b); }
};
struct plus_operator_monoid {
    typedef int underlying_type;
    typedef int target_type;
    int identity() const { return 0; }
    int apply(underlying_type a, target_type b) const { return min(inf, a + b); }
    int compose(underlying_type a, underlying_type b) const { return a + b; }
};

int main() {
    // input
    int n; scanf("%d", &n);
    vector<bool> b(n);
    REP (i, n) {
        int b_i; scanf("%d", &b_i);
        b[i] = b_i;
    }
    int q; scanf("%d", &q);
    vector<int> l(q), r(q);
    REP (i, q) {
        scanf("%d%d", &l[i], &r[i]);
        -- l[i];
    }
    // solve
    vector<int> zero(n + 1);
    REP (i, n) {
        zero[i + 1] = zero[i] + not b[i];
    }
    vector<vector<int> > from_l(n);
    REP (i, q) {
        from_l[l[i]].push_back(i);
    }
    lazy_propagation_segment_tree<min_monoid, plus_operator_monoid> segtree(n + 1);
    segtree.point_set(0, 0);
    REP (l_i, n) {
        for (int i : from_l[l_i]) {
            int value = segtree.range_concat(l_i, r[i] + 1) + zero[r[i]];
            segtree.point_set(r[i], value - zero[r[i]]);
        }
        int x = segtree.range_concat(l_i,     l_i + 1) + zero[l_i    ] + b[l_i];
        int y = segtree.range_concat(l_i + 1, l_i + 2) + zero[l_i + 1];
        segtree.point_set(l_i + 1, min(x, y) - zero[l_i + 1]);
    }
    // output
    int result = segtree.range_concat(n, n + 1) + zero[n];
    printf("%d\n", result);
    return 0;
}
```
