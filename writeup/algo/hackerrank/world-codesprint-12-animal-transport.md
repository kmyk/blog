---
layout: post
alias: "/blog/2017/12/31/hackerrank-world-codesprint-12-animal-transport/"
date: "2017-12-31T16:26:49+09:00"
tags: [ "competitive", "writeup", "hackerrank", "codesprint", "dp", "segment-tree", "lazy-propagation" ]
"target_url": [ "https://www.hackerrank.com/contests/world-codesprint-12/challenges/animal-transport" ]
---

# HackerRank World CodeSprint 12: Animal Transport

## problem

動物園が$m$個あり、動物は$n$匹いる。
それぞれの動物に対し次が定まっている: 象/犬/猫/鼠のいずれかの種類、最初に居る動物園、移動したい先の動物園。
ひとつのトラックを動物園$1$から$m$まで一直線に走らせ、適当に積み降ろしをして動物を運搬する。
ただし動物の種類の組み合わせによっては同時には乗せられず、全ては運び切れないこともある。
合計で$x$匹を運搬したいとき最小で何番目の動物園まで走れば達成できるか、全ての$x$について答えよ。

## solution

DP。segment木。$O(m \log m)$。

$x$番目の動物園までに運べる動物の数を$\mathrm{dp}(x)$とし、トラックは空だとしておく。
区間$[l, r]$中で運べる動物の数を$f(l, r)$とおいて、遷移は$\mathrm{dp}( r) = \max \\{ \mathrm{dp}(l) + f(l, r) \mid l \lt r \\}$。
$f(l, r)$の形からsegment木 (特にstarry sky tree)で加速できる。
ただし象猫と犬鼠に分けそれぞれ考える必要があり木は$2$本生える。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define REP_R(i, n) for (int i = (n) - 1; (i) >= 0; -- (i))
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
struct max_monoid {
    typedef int underlying_type;
    int unit() const { return 0; }
    int append(int a, int b) const { return max(a, b); }
};
struct plus_operator_monoid {
    typedef int underlying_type;
    typedef int target_type;
    int identity() const { return 0; }
    int apply(underlying_type a, target_type b) const { return a + b; }
    int compose(underlying_type a, underlying_type b) const { return a + b; }
};
typedef lazy_propagation_segment_tree<max_monoid, plus_operator_monoid> starry_sky_tree;

int main() {
    int testcase; scanf("%d", &testcase);
    while (testcase --) {
        // input
        int m, n; scanf("%d%d", &m, &n);
        vector<char> t(n); REP (i, n) scanf(" %c", &t[i]);
        vector<int> s(n); REP (i, n) { scanf("%d", &s[i]); -- s[i]; }
        vector<int> d(n); REP (i, n) { scanf("%d", &d[i]); -- d[i]; }
        // solve
        vector<vector<int> > from_d(m);
        REP (i, n) {
            if (s[i] < d[i]) {
                from_d[d[i]].push_back(i);
            }
        }
        vector<int> dp(m);
        array<starry_sky_tree, 2> segtree;
        REP (p, 2) segtree[p] = starry_sky_tree(m + 1);
        REP (x, m) {
            for (int i : from_d[x]) {
                const char *table = "EDCM";
                int p = (strchr(table, t[i]) - table) % 2;
                segtree[p].range_apply(0, s[i] + 1, 1);
            }
            dp[x] = max(
                segtree[0].range_concat(0, x + 1),
                segtree[1].range_concat(0, x + 1));
            REP (p, 2) {
                segtree[p].range_apply(x, x + 1, dp[x]);
            }
        }
        // output
        int y = 1;
        for (int x = 0; ; ++ y) {
            while (x < m and dp[x] < y) ++ x;
            if (x == m) break;
            printf("%d ", x + 1);
        }
        for (; y <= n; ++ y) printf("-1%c", y < n ? ' ' : '\n');
    }
    return 0;
}
```
