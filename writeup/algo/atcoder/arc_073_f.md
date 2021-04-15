---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc_073_f/
  - /writeup/algo/atcoder/arc-073-f/
  - /blog/2018/01/15/arc-073-f/
date: "2018-01-15T15:32:15+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "dp", "segment-tree", "lazy-propagation" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc073/tasks/arc073_d" ]
---

# AtCoder Regular Contest 073: F - Many Moves

## solution

DP。単純には$i$番目のマスまで動かしたとき(最後に動かしたコマは必ず座標$x\_i$にいるが)動かさなかった方のコマが座標$j$にいる状況になるまでの経過時間の最小値を$\mathrm{dp}(i, j)$とする。
このままでは$O(NQ)$で間に合わないので、区間加算と区間最小値の遅延伝播segment木を用いて座標で傾斜を付けた$\mathrm{dp}(i, j) + j$と$\mathrm{dp}(i, j) - j$を管理して上手くやる。
つまり実家。$O(Q \log N)$。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define REP_R(i, n) for (int i = int(n) - 1; (i) >= 0; -- (i))
#define ALL(x) begin(x), end(x)
using ll = long long;
using namespace std;
template <class T> inline void chmin(T & a, T const & b) { a = min(a, b); }

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

constexpr ll inf = ll(1e18) + 9;
struct min_monoid {
    typedef ll underlying_type;
    ll unit() const { return inf; }
    ll append(ll a, ll b) const { return min(a, b); }
};
struct plus_operator_monoid {
    typedef ll underlying_type;
    typedef ll target_type;
    ll identity() const { return 0; }
    ll apply(underlying_type a, target_type b) const { return min(inf, a + b); }
    ll compose(underlying_type a, underlying_type b) const { return a + b; }
};

int main() {
    // input
    int n, q, a, b; scanf("%d%d%d%d", &n, &q, &a, &b);
    -- a; -- b;
    vector<int> x(q);
    REP (i, q) {
        scanf("%d", &x[i]);
        -- x[i];
    }
    // solve
    lazy_propagation_segment_tree<min_monoid, plus_operator_monoid> segtree_l(n);
    lazy_propagation_segment_tree<min_monoid, plus_operator_monoid> segtree_r(n);
    segtree_l.point_set(b, abs(x[0] - a) - b);
    segtree_l.point_set(a, abs(x[0] - b) - a);
    segtree_r.point_set(b, abs(x[0] - a) + b);
    segtree_r.point_set(a, abs(x[0] - b) + a);
    REP (i, q - 1) {
        int delta = abs(x[i + 1] - x[i]);
        ll l = segtree_l.range_concat(x[i], x[i] + 1) + x[i];
        ll r = segtree_r.range_concat(x[i], x[i] + 1) - x[i];
        if (segtree_l.range_concat(x[i], x[i] + 1) != inf or segtree_r.range_concat(x[i], x[i] + 1) != inf) assert (l == r);
        ll from_l = segtree_l.range_concat(0, x[i + 1] + 1) + x[i + 1];
        ll from_r = segtree_r.range_concat(x[i + 1],     n) - x[i + 1];
        segtree_l.range_apply(0, n, delta);
        segtree_r.range_apply(0, n, delta);
        ll f = min({ l + delta, r + delta, from_l, from_r });
        segtree_l.point_set(x[i], f - x[i]);
        segtree_r.point_set(x[i], f + x[i]);
    }
    // output
    ll result = inf;
    REP (i, n) {
        ll l = segtree_l.range_concat(i, i + 1) + i;
        ll r = segtree_r.range_concat(i, i + 1) - i;
        if (segtree_l.range_concat(i, i + 1) != inf or segtree_r.range_concat(i, i + 1) != inf) assert (l == r);
        chmin(result, l);
    }
    printf("%lld\n", result);
    return 0;
}
```
