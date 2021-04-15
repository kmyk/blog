---
layout: post
redirect_from:
  - /writeup/algo/hackerrank/world-codesprint-12-factorial-array/
  - /blog/2017/12/31/hackerrank-world-codesprint-12-factorial-array/
date: "2017-12-31T16:26:43+09:00"
tags: [ "competitive", "writeup", "hackerrank", "codesprint", "lazy-propagation", "segment-tree", "query" ]
"target_url": [ "https://www.hackerrank.com/contests/world-codesprint-12/challenges/factorial-array" ]
---

# HackerRank World CodeSprint 12: Factorial Array

$10^9+7$と誤読すると解けない。気を付けよう。
ついでに$1$減らすクエリがあっても難しくなる (無理矢理やれば解けそうだが)。

## problem

数列$A$が与えられる。次のようなクエリがたくさん与えられるので処理せよ。

1.  区間$[l, r]$が与えられる。$i \in [l, r]$のそれぞれに対し$A\_i$を$1$増やせ。
2.  区間$[l, r]$が与えられる。$i \in [l, r]$のそれぞれに対し階乗$A\_i!$を考え、その総和を$\bmod 10^9$で答えよ。
3.  添字$i$と値$v$が与えられる。$A\_i$に$v$を代入せよ。

## solution

法が$10^9$なのですぐに$0$になる。
$40! \equiv 0 \bmod 10^9$なので区間中の$40$以下の数を数えておくようなsegment木を書く。
$O((N + Q) \log N)$。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define REP_R(i, n) for (int i = (n) - 1; (i) >= 0; -- (i))
using ll = long long;
using namespace std;

template <class Monoid, class OperatorMonoid>
struct lazy_propagation_segment_tree { // on monoids
    static_assert (is_same<typename Monoid::underlying_type, typename OperatorMonoid::target_type>::value, "");
    typedef typename Monoid::underlying_type underlying_type;
    typedef typename OperatorMonoid::underlying_type operator_type;
    Monoid mon;
    OperatorMonoid op;
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

template <int N>
struct count_monoid {
    typedef array<int, N> underlying_type;
    underlying_type unit() const { return underlying_type(); }
    underlying_type append(underlying_type a, underlying_type b) const {
        underlying_type c = {};
        REP (i, N) c[i] = a[i] + b[i];
        return c;
    }
};
template <int N>
struct increment_operator_monoid {
    typedef int underlying_type;
    typedef array<int, N> target_type;
    underlying_type identity() const { return 0; }
    target_type apply(underlying_type a, target_type b) const {
        if (a == 0) return b;
        target_type c = {};
        REP (i, N - a) c[i + a] = b[i];
        return c;
    }
    underlying_type compose(underlying_type a, underlying_type b) const { return a + b; }
};

constexpr int mod = 1e9;  // not 1e9+7
constexpr int width = 41;
int main() {
    // prepare
    int fact[width] = {};
    fact[0] = 1;
    REP (i, width - 1) {
        fact[i + 1] = fact[i] *(ll) (i + 1) % mod;
    }
    // input initial values
    int n, m; scanf("%d%d", &n, &m);
    lazy_propagation_segment_tree<count_monoid<width>, increment_operator_monoid<width> > a(n);
    auto point_set = [&](int i, int a_i) {
        auto cnt = a.mon.unit();
        if (a_i < width) {
            cnt[a_i] = 1;
        }
        a.point_set(i, cnt);
    };
    REP (i, n) {
        int a_i; scanf("%d", &a_i);
        point_set(i, a_i);
    }
    // operate
    while (m --) {
        int type; scanf("%d", &type);
        if (type == 1) {
            int l, r; scanf("%d%d", &l, &r); -- l;
            a.range_apply(l, r, 1);
        } else if (type == 2) {
            int l, r; scanf("%d%d", &l, &r); -- l;
            auto cnt = a.range_concat(l, r);
            ll acc = 0;
            REP (i, width) {
                acc += fact[i] *(ll) cnt[i] % mod;
            }
            printf("%lld\n", acc % mod);
        } else if (type == 3) {
            int i, a_i; scanf("%d%d", &i, &a_i); -- i;
            point_set(i, a_i);
        }
    }
    return 0;
}
```
