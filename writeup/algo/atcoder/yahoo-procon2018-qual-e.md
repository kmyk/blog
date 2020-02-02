---
layout: post
alias: "/blog/2018/02/14/yahoo-procon2018-qual-e/"
title: "「みんなのプロコン 2018」: E - グラフの問題"
date: "2018-02-14T20:15:29+09:00"
tags: [ "competitive", "writeup", "atcoder", "yahoo-procon", "segment-tree", "binary-search", "greedy", "graph" ]
"target_url": [ "https://beta.atcoder.jp/contests/yahoo-procon2018-qual/tasks/yahoo_procon2018_qual_e" ]
---

これは$400$点ぐらいしかなくない？
実装部分だけならHackerRankで見た。
ちゃんと証明しろと言われると難しいが。

DばかりやってEをまったく開かなかったのは反省。
開いてさえいれば「みんな」になれたはずなのに

## solution

握手補題から$\sum d\_i$が奇数なら`YES`ではない。
奇数なら次数の最も小さい頂点に$+1$する。
あとは貪欲。segment木。
$O(N (\log N)^2)$。

貪欲部分について。
次数列を修正していく。
次数の大きい頂点から見る。その次数を$d\_i$とする。
他の頂点を次数の大きい順に$d\_i$個 貪欲に選び、それらとの間に辺を張る。
張った辺に応じて次数列を修正。
$0$になった頂点は削除。
これで全て$0$にできれば`ABSOLUTELY NO`ではない。


## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define REP_R(i, n) for (int i = int(n) - 1; (i) >= 0; -- (i))
#define ALL(x) begin(x), end(x)
using ll = long long;
using namespace std;

template <class OperatorMonoid>
struct dual_segment_tree {
    typedef typename OperatorMonoid::underlying_type operator_type;
    typedef typename OperatorMonoid::target_type underlying_type;
    int n;
    vector<operator_type> f;
    vector<underlying_type> a;
    const OperatorMonoid op;
    dual_segment_tree() = default;
    dual_segment_tree(int a_n, underlying_type initial_value, OperatorMonoid const & a_op = OperatorMonoid()) : op(a_op) {
        n = 1; while (n < a_n) n *= 2;
        a.resize(n, initial_value);
        f.resize(n-1, op.unit());
    }
    underlying_type point_get(int i) { // 0-based
        underlying_type acc = a[i];
        for (i = (i+n)/2; i > 0; i /= 2) { // 1-based
            acc = op.apply(f[i-1], acc);
        }
        return acc;
    }
    void range_apply(int l, int r, operator_type z) { // 0-based, [l, r)
        assert (0 <= l and l <= r and r <= n);
        range_apply(0, 0, n, l, r, z);
    }
    void range_apply(int i, int il, int ir, int l, int r, operator_type z) {
        if (l <= il and ir <= r) { // 0-based
            if (i < f.size()) {
                f[i] = op.append(z, f[i]);
            } else {
                a[i-n+1] = op.apply(z, a[i-n+1]);
            }
        } else if (ir <= l or r <= il) {
            // nop
        } else {
            range_apply(2*i+1, il, (il+ir)/2, 0, n, f[i]);
            range_apply(2*i+2, (il+ir)/2, ir, 0, n, f[i]);
            f[i] = op.unit();
            range_apply(2*i+1, il, (il+ir)/2, l, r, z);
            range_apply(2*i+2, (il+ir)/2, ir, l, r, z);
        }
    }
};
struct plus_operator_monoid {
    typedef int underlying_type;
    typedef int target_type;
    int unit() const { return 0; }
    int append(int a, int b) const { return a + b; }
    int apply(int a, int b) const { return a + b; }
};

template <typename UnaryPredicate>
int64_t binsearch(int64_t l, int64_t r, UnaryPredicate p) {
    assert (l <= r);
    -- l;
    while (r - l > 1) {
        int64_t m = l + (r - l) / 2;  // avoid overflow
        (p(m) ? r : l) = m;
    }
    return r;
}

int main() {
    // input
    int n; scanf("%d", &n);
    vector<int> d(n); REP (i, n) scanf("%d", &d[i]);

    // solve
    ll sum_d = accumulate(ALL(d), 0ll);
    sort(ALL(d));
    if (sum_d % 2 == 1) {
        int r = binsearch(0, n, [&](int j) { return d[0] < d[j]; });
        d[r - 1] += 1;
    }
    bool result = true;
    dual_segment_tree<plus_operator_monoid> segtree(n, 0);
    REP (i, n) segtree.range_apply(i, i + 1, d[i]);
    REP_R (i, n) {
        int d_i = segtree.point_get(i);
        if (d_i == 0) break;
        if (i - d_i < 0) { result = false; break; }
        int d_j = segtree.point_get(i - d_i);
        if (d_j == 0) { result = false; break; }
        int l = binsearch(0, i, [&](int k) { return d_j <= segtree.point_get(k); });
        int r = binsearch(l, i, [&](int k) { return d_j <  segtree.point_get(k); });
        segtree.range_apply(r, i, -1);
        segtree.range_apply(l, l + (d_i - (i - r)), -1);
    }

    // result
    printf("%s\n", result ? (sum_d % 2 == 0 ? "YES" : "NO") : "ABSOLUTELY NO");
    return 0;
}
```
